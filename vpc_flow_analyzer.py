#!/usr/bin/env python3
import pandas as pd
import ipaddress
import argparse
import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any, Optional, Generator

class VPCFlowLogAnalyzer:
    def __init__(self, log_file: str, chunk_size: int = 100000):
        """
        Initialize the VPC Flow Log Analyzer
        
        :param log_file: Path to the VPC flow log file
        :param chunk_size: Number of rows to process in each chunk
        """
        self.console = Console()
        self.log_file = log_file
        self.chunk_size = chunk_size
        self.df = None
        self._load_log_file()
    
    def _load_log_file(self):
        """
        Load VPC flow log file into chunks
        """
        try:
            # Use iterator to load file in chunks
            chunks = pd.read_csv(
                self.log_file, 
                sep=' ', 
                header=None, 
                names=[
                    'version', 'account_id', 'interface_id', 
                    'srcaddr', 'dstaddr', 'srcport', 
                    'dstport', 'protocol', 'packets', 
                    'bytes', 'start', 'end', 'action', 
                    'log_status'
                ],
                chunksize=self.chunk_size
            )
            
            # Concatenate chunks, but limit total memory usage
            self.df = pd.concat(list(chunks)[:10])  # Limit to first 1 million rows
            
            # Free up memory
            del chunks
        except Exception as e:
            self.console.print(f"[bold red]Error loading log file: {e}[/bold red]")
            self.df = pd.DataFrame()
    
    def summarize_traffic(self) -> Dict[str, Any]:
        """
        Generate a summary of network traffic
        
        :return: Dictionary with traffic summary metrics
        """
        if self.df is None or self.df.empty:
            return {}
        
        return {
            'total_connections': len(self.df),
            'unique_source_ips': self.df['srcaddr'].nunique(),
            'unique_destination_ips': self.df['dstaddr'].nunique(),
            'accepted_connections': len(self.df[self.df['action'] == 'ACCEPT']),
            'rejected_connections': len(self.df[self.df['action'] == 'REJECT'])
        }
    
    def generate_security_group_suggestions(self, max_suggestions: int = 10, top_n_connections: int = 100) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Generate concise security group ingress and egress rule suggestions per ENI
        
        :param max_suggestions: Maximum number of suggestions per ENI
        :param top_n_connections: Number of top connections to analyze
        :return: Dictionary of suggested security group rules per ENI
        """
        suggestions = {
            'ingress_rules': {},
            'egress_rules': {}
        }
        
        # Analyze accepted connections for potential ingress rules
        accepted_connections = self.df[self.df['action'] == 'ACCEPT']
        
        # Sort by connection count to get most significant connections
        ingress_grouped = (
            accepted_connections.groupby(['interface_id', 'dstport', 'protocol', 'srcaddr'])
            .size()
            .reset_index(name='connection_count')
            .sort_values('connection_count', ascending=False)
            .head(top_n_connections)
        )
        
        # Track potential ingress security group rules per ENI
        for _, row in ingress_grouped.iterrows():
            eni = row['interface_id']
            port = row['dstport']
            protocol = row['protocol']
            src_ip = row['srcaddr']
            connection_count = row['connection_count']
            
            protocol_details = self._get_protocol_details(str(protocol))
            
            # Initialize ENI in suggestions if not exists
            if eni not in suggestions['ingress_rules']:
                suggestions['ingress_rules'][eni] = []
            
            # Add rule suggestion if not exceeded max suggestions
            if len(suggestions['ingress_rules'][eni]) < max_suggestions:
                # Check if similar rule already exists to prevent duplicates
                existing_rule = next((
                    rule for rule in suggestions['ingress_rules'][eni] 
                    if rule['port'] == port and rule['protocol_number'] == protocol
                ), None)
                
                if not existing_rule:
                    suggestions['ingress_rules'][eni].append({
                        'port': port,
                        'protocol_number': protocol,
                        'protocol_name': protocol_details['name'],
                        'protocol_description': protocol_details['description'],
                        'common_uses': protocol_details['common_uses'],
                        'source_ip': src_ip,
                        'connection_count': connection_count
                    })
        
        # Analyze egress connections similarly
        egress_grouped = (
            accepted_connections.groupby(['interface_id', 'srcport', 'protocol', 'dstaddr'])
            .size()
            .reset_index(name='connection_count')
            .sort_values('connection_count', ascending=False)
            .head(top_n_connections)
        )
        
        # Track potential egress security group rules per ENI
        for _, row in egress_grouped.iterrows():
            eni = row['interface_id']
            port = row['srcport']
            protocol = row['protocol']
            dst_ip = row['dstaddr']
            connection_count = row['connection_count']
            
            protocol_details = self._get_protocol_details(str(protocol))
            
            # Initialize ENI in suggestions if not exists
            if eni not in suggestions['egress_rules']:
                suggestions['egress_rules'][eni] = []
            
            # Add rule suggestion if not exceeded max suggestions
            if len(suggestions['egress_rules'][eni]) < max_suggestions:
                # Check if similar rule already exists to prevent duplicates
                existing_rule = next((
                    rule for rule in suggestions['egress_rules'][eni] 
                    if rule['port'] == port and rule['protocol_number'] == protocol
                ), None)
                
                if not existing_rule:
                    suggestions['egress_rules'][eni].append({
                        'port': port,
                        'protocol_number': protocol,
                        'protocol_name': protocol_details['name'],
                        'protocol_description': protocol_details['description'],
                        'common_uses': protocol_details['common_uses'],
                        'destination_ip': dst_ip,
                        'connection_count': connection_count
                    })
        
        return suggestions
    
    def _get_protocol_details(self, protocol: str) -> Dict[str, Any]:
        """
        Get detailed protocol information
        
        :param protocol: Protocol number
        :return: Dictionary with protocol details
        """
        protocol_map = {
            '6': {
                'name': 'TCP',
                'description': 'Transmission Control Protocol - Connection-oriented, reliable communication',
                'common_uses': ['HTTP', 'HTTPS', 'SSH', 'SMTP']
            },
            '17': {
                'name': 'UDP', 
                'description': 'User Datagram Protocol - Connectionless, faster communication',
                'common_uses': ['DNS', 'VoIP', 'Streaming']
            },
            '1': {
                'name': 'ICMP',
                'description': 'Internet Control Message Protocol - Network diagnostics and error reporting',
                'common_uses': ['Ping', 'Traceroute']
            },
            '58': {
                'name': 'ICMPv6',
                'description': 'Internet Control Message Protocol version 6 - Network diagnostics for IPv6',
                'common_uses': ['IPv6 Ping', 'IPv6 Neighbor Discovery']
            }
        }
        return protocol_map.get(protocol, {
            'name': f'Unknown Protocol {protocol}',
            'description': 'Unrecognized protocol number',
            'common_uses': []
        })
    
    def visualize_traffic(self, top_n: int = 10):
        """
        Create visualizations of network traffic
        
        :param top_n: Number of top ports to visualize
        """
        plt.figure(figsize=(12, 6))
        
        # Top source ports
        plt.subplot(1, 2, 1)
        self.df['srcport'].value_counts().head(top_n).plot(kind='bar')
        plt.title(f'Top {top_n} Source Ports')
        plt.xlabel('Port')
        plt.ylabel('Connection Count')
        plt.xticks(rotation=45)
        
        # Top destination ports
        plt.subplot(1, 2, 2)
        self.df['dstport'].value_counts().head(top_n).plot(kind='bar')
        plt.title(f'Top {top_n} Destination Ports')
        plt.xlabel('Port')
        plt.ylabel('Connection Count')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig('vpc_traffic_analysis.png')
        self.console.print(f"[bold green]Traffic visualization saved as vpc_traffic_analysis.png[/bold green]")

def main():
    parser = argparse.ArgumentParser(description='AWS VPC Flow Log Analyzer')
    parser.add_argument('log_file', help='Path to VPC flow log file')
    args = parser.parse_args()
    
    console = Console()
    
    console.print(Panel.fit(
        "[bold cyan]AWS VPC Flow Log Analyzer[/bold cyan]\n"
        "Parsing and analyzing network traffic logs"
    ))
    
    analyzer = VPCFlowLogAnalyzer(args.log_file)
    
    # Display traffic summary
    traffic_summary = analyzer.summarize_traffic()
    if traffic_summary:
        table = Table(title="VPC Flow Log Traffic Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Connections", str(traffic_summary['total_connections']))
        table.add_row("Unique Source IPs", str(traffic_summary['unique_source_ips']))
        table.add_row("Unique Destination IPs", str(traffic_summary['unique_destination_ips']))
        table.add_row("Accepted Connections", str(traffic_summary['accepted_connections']))
        table.add_row("Rejected Connections", str(traffic_summary['rejected_connections']))
        
        console.print(table)
    
    # Generate security group suggestions
    security_suggestions = analyzer.generate_security_group_suggestions()
    
    # Display security group suggestions
    console.print("\n[bold green]Security Group Rule Suggestions:[/bold green]")
    
    # Ingress Rules
    for eni, rules in security_suggestions['ingress_rules'].items():
        console.print(f"\n[bold]ENI {eni} Ingress Rules:[/bold]")
        for i, rule in enumerate(rules, 1):
            console.print(f"\nRule {i}:")
            console.print(f"  [cyan]Port:[/cyan] {rule['port']}")
            console.print(f"  [cyan]Protocol Number:[/cyan] {rule['protocol_number']}")
            console.print(f"  [cyan]Protocol Name:[/cyan] {rule['protocol_name']}")
            console.print(f"  [cyan]Protocol Description:[/cyan] {rule['protocol_description']}")
            console.print(f"  [cyan]Common Uses:[/cyan] {', '.join(rule['common_uses'])}")
            console.print(f"  [cyan]Source IP:[/cyan] {rule['source_ip']}")
            console.print(f"  [cyan]Connection Count:[/cyan] {rule['connection_count']}")
    
    # Egress Rules
    for eni, rules in security_suggestions['egress_rules'].items():
        console.print(f"\n[bold]ENI {eni} Egress Rules:[/bold]")
        for i, rule in enumerate(rules, 1):
            console.print(f"\nRule {i}:")
            console.print(f"  [cyan]Port:[/cyan] {rule['port']}")
            console.print(f"  [cyan]Protocol Number:[/cyan] {rule['protocol_number']}")
            console.print(f"  [cyan]Protocol Name:[/cyan] {rule['protocol_name']}")
            console.print(f"  [cyan]Protocol Description:[/cyan] {rule['protocol_description']}")
            console.print(f"  [cyan]Common Uses:[/cyan] {', '.join(rule['common_uses'])}")
            console.print(f"  [cyan]Destination IP:[/cyan] {rule['destination_ip']}")
            console.print(f"  [cyan]Connection Count:[/cyan] {rule['connection_count']}")
    
    # Create traffic visualizations
    analyzer.visualize_traffic()

if __name__ == '__main__':
    main()
