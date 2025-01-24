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
        Load VPC flow log file into chunks with extended column support
        """
        try:
            # Define all possible columns
            columns = [
                'version', 'account-id', 'interface-id', 
                'srcaddr', 'dstaddr', 'srcport', 
                'dstport', 'protocol', 'packets', 
                'bytes', 'start', 'end', 'action', 
                'log-status', 'vpc-id', 'subnet-id', 
                'instance-id', 'tcp-flags', 'type', 
                'region', 'az-id', 'reject-reason',
                'flow-direction', 'traffic-path', 
                'pkt-srcaddr', 'pkt-dstaddr', 
                'pkt-src-aws-service', 'pkt-dst-aws-service',
                'ecs-cluster-name', 'ecs-cluster-arn', 
                'ecs-container-instance-id', 'ecs-container-instance-arn', 
                'ecs-service-name', 'ecs-task-definition-arn', 
                'ecs-task-id', 'ecs-task-arn', 
                'ecs-container-id', 'ecs-second-container-id',
                'sublocation-id', 'sublocation-type'
            ]
            
            # Use iterator to load file in chunks
            chunks = pd.read_csv(
                self.log_file, 
                sep=' ', 
                header=None, 
                names=columns,
                chunksize=self.chunk_size,
                low_memory=False
            )
            
            # Concatenate chunks, but limit total memory usage
            self.df = pd.concat(list(chunks)[:10])  # Limit to first 1 million rows
            
            # Free up memory
            del chunks
            
            # Convert numeric columns
            numeric_columns = ['srcport', 'dstport', 'packets', 'bytes', 'start', 'end']
            for col in numeric_columns:
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
        
        except Exception as e:
            self.console.print(f"[bold red]Error loading log file: {e}[/bold red]")
            self.df = pd.DataFrame()
    
    def summarize_traffic(self) -> Dict[str, Any]:
        """
        Generate a comprehensive summary of network traffic
        
        :return: Dictionary with traffic summary metrics
        """
        if self.df is None or self.df.empty:
            return {}
        
        summary = {
            'total_connections': len(self.df),
            'unique_source_ips': self.df['srcaddr'].nunique(),
            'unique_destination_ips': self.df['dstaddr'].nunique(),
            'accepted_connections': len(self.df[self.df['action'] == 'ACCEPT']),
            'rejected_connections': len(self.df[self.df['action'] == 'REJECT']),
            'total_bytes_transferred': self.df['bytes'].sum(),
            'total_packets': self.df['packets'].sum(),
            'unique_vpcs': self.df['vpc-id'].nunique(),
            'unique_subnets': self.df['subnet-id'].nunique(),
            'unique_regions': self.df['region'].nunique(),
            'unique_availability_zones': self.df['az-id'].nunique()
        }
        
        # Analyze AWS services
        summary['src_aws_services'] = self.df['pkt-src-aws-service'].value_counts().to_dict()
        summary['dst_aws_services'] = self.df['pkt-dst-aws-service'].value_counts().to_dict()
        
        return summary
    
    def analyze_ecs_traffic(self) -> Dict[str, Any]:
        """
        Analyze ECS-specific network traffic
        
        :return: Dictionary with ECS traffic insights
        """
        if self.df is None or self.df.empty:
            return {}
        
        # ECS Cluster Analysis
        ecs_summary = {
            'unique_clusters': self.df['ecs-cluster-name'].nunique(),
            'unique_services': self.df['ecs-service-name'].nunique(),
            'unique_tasks': self.df['ecs-task-id'].nunique(),
            'unique_container_instances': self.df['ecs-container-instance-id'].nunique()
        }
        
        # Top ECS Clusters by Traffic
        ecs_summary['top_clusters'] = (
            self.df.groupby('ecs-cluster-name')['bytes']
            .sum()
            .nlargest(5)
            .to_dict()
        )
        
        # Top ECS Services by Traffic
        ecs_summary['top_services'] = (
            self.df.groupby('ecs-service-name')['bytes']
            .sum()
            .nlargest(5)
            .to_dict()
        )
        
        return ecs_summary
    
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
            accepted_connections.groupby(['interface-id', 'dstport', 'protocol', 'srcaddr'])
            .agg({
                'bytes': 'sum',
                'packets': 'sum'
            })
            .reset_index()
            .sort_values('bytes', ascending=False)
            .head(top_n_connections)
        )
        
        # Track potential ingress security group rules per ENI
        for _, row in ingress_grouped.iterrows():
            eni = row['interface-id']
            port = row['dstport']
            protocol = row['protocol']
            src_ip = row['srcaddr']
            bytes_transferred = row['bytes']
            packets_transferred = row['packets']
            
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
                        'bytes_transferred': bytes_transferred,
                        'packets_transferred': packets_transferred
                    })
        
        # Similar analysis for egress rules
        egress_grouped = (
            accepted_connections.groupby(['interface-id', 'srcport', 'protocol', 'dstaddr'])
            .agg({
                'bytes': 'sum',
                'packets': 'sum'
            })
            .reset_index()
            .sort_values('bytes', ascending=False)
            .head(top_n_connections)
        )
        
        # Track potential egress security group rules per ENI
        for _, row in egress_grouped.iterrows():
            eni = row['interface-id']
            port = row['srcport']
            protocol = row['protocol']
            dst_ip = row['dstaddr']
            bytes_transferred = row['bytes']
            packets_transferred = row['packets']
            
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
                        'bytes_transferred': bytes_transferred,
                        'packets_transferred': packets_transferred
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
        plt.figure(figsize=(15, 10))
        
        # Top source ports by bytes
        plt.subplot(2, 2, 1)
        self.df.groupby('srcport')['bytes'].sum().nlargest(top_n).plot(kind='bar')
        plt.title(f'Top {top_n} Source Ports by Bytes')
        plt.xlabel('Port')
        plt.ylabel('Total Bytes')
        plt.xticks(rotation=45)
        
        # Top destination ports by bytes
        plt.subplot(2, 2, 2)
        self.df.groupby('dstport')['bytes'].sum().nlargest(top_n).plot(kind='bar')
        plt.title(f'Top {top_n} Destination Ports by Bytes')
        plt.xlabel('Port')
        plt.ylabel('Total Bytes')
        plt.xticks(rotation=45)
        
        # Traffic by AWS Services
        plt.subplot(2, 2, 3)
        service_traffic = self.df.groupby('pkt-src-aws-service')['bytes'].sum().nlargest(top_n)
        service_traffic.plot(kind='pie', autopct='%1.1f%%')
        plt.title('Source AWS Service Traffic')
        
        plt.subplot(2, 2, 4)
        service_traffic = self.df.groupby('pkt-dst-aws-service')['bytes'].sum().nlargest(top_n)
        service_traffic.plot(kind='pie', autopct='%1.1f%%')
        plt.title('Destination AWS Service Traffic')
        
        plt.tight_layout()
        plt.savefig('vpc_traffic_analysis.png')
        self.console.print(f"[bold green]Traffic visualization saved as vpc_traffic_analysis.png[/bold green]")

def main():
    parser = argparse.ArgumentParser(description='AWS VPC Flow Log Analyzer')
    parser.add_argument('log_file', help='Path to the VPC flow log file')
    args = parser.parse_args()
    
    console = Console()
    
    try:
        analyzer = VPCFlowLogAnalyzer(args.log_file)
        
        # Display traffic summary
        traffic_summary = analyzer.summarize_traffic()
        if traffic_summary:
            table = Table(title="VPC Flow Log Traffic Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="magenta")
            
            for metric, value in traffic_summary.items():
                table.add_row(str(metric).replace('_', ' ').title(), str(value))
            
            console.print(table)
        
        # ECS Traffic Analysis
        ecs_summary = analyzer.analyze_ecs_traffic()
        if ecs_summary:
            ecs_table = Table(title="ECS Traffic Summary")
            ecs_table.add_column("Metric", style="cyan")
            ecs_table.add_column("Value", style="magenta")
            
            for metric, value in ecs_summary.items():
                ecs_table.add_row(str(metric).replace('_', ' ').title(), str(value))
            
            console.print(ecs_table)
        
        # Generate security group suggestions
        security_suggestions = analyzer.generate_security_group_suggestions()
        
        # Visualize traffic
        analyzer.visualize_traffic()
    
    except Exception as e:
        console.print(f"[bold red]Error analyzing log file: {e}[/bold red]")

if __name__ == '__main__':
    main()
