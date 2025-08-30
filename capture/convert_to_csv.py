# import sys
# import os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import os
# import subprocess
# from traffic_generator.utils import timestamped_filename

# def convert_pcap_to_csv(pcap_path, output_dir="data/processed"):
#     # Make sure output directory exists
#     os.makedirs(output_dir, exist_ok=True)
    
#     # Convert relative paths to absolute
#     abs_pcap_path = os.path.abspath(pcap_path)
    
#     # Check if file exists
#     if not os.path.exists(abs_pcap_path):
#         print(f"Error: PCAP file not found: {abs_pcap_path}")
#         return None
    
#     csv_name = timestamped_filename("traffic", "csv")
#     output_path = os.path.join(output_dir, csv_name)

#     fields = [
#         "-e", "frame.time",
#         "-e", "ip.src",
#         "-e", "ip.dst",
#         "-e", "frame.len",
#         "-e", "tcp.srcport",
#         "-e", "tcp.dstport",
#         "-e", "tcp.flags",
#         "-e", "http.request.method",
#         "-e", "http.user_agent"
#     ]

#     # Try to locate tshark
#     tshark_path = "tshark"  # Default, assumes it's in PATH
    
#     # Common installation paths for Wireshark/tshark on Windows
#     possible_paths = [
#         r"C:\Program Files\Wireshark\tshark.exe",
#         r"C:\Program Files (x86)\Wireshark\tshark.exe"
#     ]
    
#     # Check if tshark exists in common locations
#     for path in possible_paths:
#         if os.path.exists(path):
#             tshark_path = path
#             break
    
#     cmd = [
#         tshark_path, "-r", abs_pcap_path, "-T", "fields",
#         *fields,
#         "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
#     ]

#     try:
#         # Create output directory if it doesn't exist
#         output_dir_path = os.path.dirname(output_path)
#         if not os.path.exists(output_dir_path):
#             os.makedirs(output_dir_path)
            
#         with open(output_path, "w") as f:
#             result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
#         if result.returncode != 0:
#             print(f"Error running tshark: {result.stderr}")
#             return None
            
#         print(f"CSV saved to: {output_path}")
#         return output_path
#     except FileNotFoundError:
#         print(f"Error: tshark not found. Please install Wireshark or add it to your system PATH.")
#         print(f"Command attempted: {' '.join(cmd)}")
#         return None

# if __name__ == "__main__":
#     # Get the script's directory
#     script_dir = os.path.dirname(os.path.abspath(__file__))
#     # Get the project root directory (one level up)
#     project_root = os.path.dirname(script_dir)
    
#     # Use absolute path to the PCAP file
#     pcap_path = os.path.join(project_root, "data", "raw", "sample.pcap")
    
#     print(f"Looking for PCAP file at: {pcap_path}")
#     convert_pcap_to_csv(pcap_path)


import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import os
import subprocess
import tempfile
import pandas as pd
from datetime import datetime
from traffic_generator.utils import timestamped_filename

def convert_pcap_to_csv(pcap_path, output_dir="data/processed"):
    """
    Convert PCAP file to CSV with the specific features required for ML model:
    - StartTime
    - Dur (Duration)
    - Proto (Protocol)
    - SrcAddr (Source Address)
    - DstAddr (Destination Address)
    - State (Connection State)
    - TotPkts (Total Packets)
    - TotBytes (Total Bytes)
    - SrcBytes (Source Bytes)
    - Label (for classification)
    """
    # Make sure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Convert relative paths to absolute
    abs_pcap_path = os.path.abspath(pcap_path)
    
    # Check if file exists
    if not os.path.exists(abs_pcap_path):
        print(f"Error: PCAP file not found: {abs_pcap_path}")
        return None
    
    csv_name = timestamped_filename("traffic", "csv")
    output_path = os.path.join(output_dir, csv_name)

    # Create a temporary file for raw packet data
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
        temp_path = temp_file.name
    
    # Try to locate tshark
    tshark_path = "tshark"  # Default, assumes it's in PATH
    
    # Common installation paths for Wireshark/tshark on Windows
    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    
    # Check if tshark exists in common locations
    for path in possible_paths:
        if os.path.exists(path):
            tshark_path = path
            break
    
    # First, extract raw packet data with timestamps for flow calculation
    fields = [
        "-e", "frame.time_epoch",    # Timestamp for calculating start time and duration
        "-e", "ip.proto",            # Protocol number (will be converted to name)
        "-e", "ip.src",              # Source IP
        "-e", "ip.dst",              # Destination IP
        "-e", "tcp.srcport",         # Source port (for TCP)
        "-e", "tcp.dstport",         # Destination port (for TCP)
        "-e", "udp.srcport",         # Source port (for UDP)
        "-e", "udp.dstport",         # Destination port (for UDP)
        "-e", "frame.len",           # Frame length for calculating bytes
        "-e", "tcp.flags",           # TCP flags for determining connection state
        "-e", "tcp.analysis.acks_frame", # Related ACK frame
        "-e", "tcp.analysis.bytes_in_flight" # Bytes in flight (helps estimate direction)
    ]
    
    cmd = [
        tshark_path, "-r", abs_pcap_path, "-T", "fields",
        *fields,
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]

    try:
        # Run tshark to get the raw packet data
        with open(temp_path, "w") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
        if result.returncode != 0:
            print(f"Error running tshark: {result.stderr}")
            os.unlink(temp_path)
            return None
        
        # Now process the raw data to calculate flow metrics
        df = pd.read_csv(temp_path)
        
        # Clean column names (removing dots)
        df.columns = [col.replace('.', '_') for col in df.columns]
        
        # Convert protocol numbers to names
        proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        df['Proto'] = df['ip_proto'].apply(lambda x: proto_map.get(int(x), 'other') if pd.notna(x) and x != '' else 'other')
        
        # Define flow identifier based on 5-tuple
        df['src_port'] = df.apply(
            lambda x: x['tcp_srcport'] if pd.notna(x['tcp_srcport']) and x['tcp_srcport'] != '' else 
                    (x['udp_srcport'] if pd.notna(x['udp_srcport']) and x['udp_srcport'] != '' else 0),
            axis=1
        )
        df['dst_port'] = df.apply(
            lambda x: x['tcp_dstport'] if pd.notna(x['tcp_dstport']) and x['tcp_dstport'] != '' else 
                    (x['udp_dstport'] if pd.notna(x['udp_dstport']) and x['udp_dstport'] != '' else 0),
            axis=1
        )
        
        # Create unique flow identifier
        df['flow_id'] = df.apply(
            lambda x: f"{x['ip_src']}:{x['src_port']}-{x['ip_dst']}:{x['dst_port']}-{x['Proto']}",
            axis=1
        )
        
        # Convert frame.time_epoch to datetime
        df['timestamp'] = pd.to_datetime(df['frame_time_epoch'].astype(float), unit='s')
        
        # Group by flow_id to calculate statistics
        flow_stats = df.groupby('flow_id').agg(
            StartTime=('timestamp', 'min'),
            EndTime=('timestamp', 'max'),
            SrcAddr=('ip_src', 'first'),
            DstAddr=('ip_dst', 'first'),
            Proto=('Proto', 'first'),
            TotPkts=('frame_len', 'count'),
            TotBytes=('frame_len', 'sum'),
        ).reset_index()
        
        # Calculate duration in seconds
        flow_stats['Dur'] = (flow_stats['EndTime'] - flow_stats['StartTime']).dt.total_seconds()
        
        # Format StartTime to match expected format (YYYY/MM/DD HH:MM:SS.mmm)
        flow_stats['StartTime'] = flow_stats['StartTime'].dt.strftime('%Y/%m/%d %H:%M:%S.%f')
        
        # Calculate SrcBytes (estimated as packets from source to destination)
        # In a more complex implementation, we'd track direction more precisely
        # For now, we'll estimate it as 60% of total bytes (simplified assumption)
        flow_stats['SrcBytes'] = (flow_stats['TotBytes'] * 0.6).astype(int)
        
        # Determine connection state based on TCP flags
        # This is a simplified approach - for more accuracy, we'd need to analyze the full TCP handshake
        def determine_state(flow_id):
            flow_packets = df[df['flow_id'] == flow_id]
            
            # Check for SYN, FIN, ACK flags in the flow
            has_syn = flow_packets['tcp_flags'].astype(str).str.contains('0x0002', na=False).any()
            has_fin = flow_packets['tcp_flags'].astype(str).str.contains('0x0001', na=False).any()
            has_ack = flow_packets['tcp_flags'].astype(str).str.contains('0x0010', na=False).any()
            has_urgent = flow_packets['tcp_flags'].astype(str).str.contains('0x0020', na=False).any()
            
            # Full handshake (SYN + FIN + ACK)
            if has_syn and has_fin and has_ack:
                return 'FSPA_FSPA'
            # Urgent pointer set
            elif has_urgent:
                return 'URP'
            # Default - established connection
            else:
                return 'CON'
        
        # Apply state determination to each flow
        flow_stats['State'] = flow_stats['flow_id'].apply(determine_state)
        
        # Add Label column (all normal traffic by default)
        # flow_stats['Label'] = 'Normal'
        
        # Select and reorder columns to match ML model requirements
        final_df = flow_stats[[
            'StartTime', 'Dur', 'Proto', 'SrcAddr', 'DstAddr', 
            'State', 'TotPkts', 'TotBytes', 'SrcBytes'
        ]]
        
        # Save to CSV
        final_df.to_csv(output_path, index=False)
        print(f"CSV saved to: {output_path}")
        
        # Clean up
        os.unlink(temp_path)
        return output_path
        
    except Exception as e:
        print(f"Error processing PCAP: {e}")
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        return None

if __name__ == "__main__":
    # Get the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Get the project root directory (one level up)
    project_root = os.path.dirname(script_dir)
    
    # Use absolute path to the PCAP file
    pcap_path = os.path.join(project_root, "data", "raw", "sample.pcap")
    
    print(f"Looking for PCAP file at: {pcap_path}")
    convert_pcap_to_csv(pcap_path)