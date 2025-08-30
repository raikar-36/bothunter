# #!/usr/bin/env python3
# """
# Wireshark Traffic Bot Detection Tool (Updated for .joblib ML Models)

# This script analyzes CSV data converted from Wireshark PCAP files
# to detect bot traffic using a pre-trained machine learning model.

# Usage:
# python detect_bot_traffic.py --csv wireshark_data.csv --model model_file.joblib --output results.csv
# """

# import os
# import sys
# import argparse
# import pandas as pd
# import numpy as np
# import joblib
# import networkx as nx
# from datetime import datetime
# import matplotlib.pyplot as plt
# from tabulate import tabulate  # For better terminal visualization

# def parse_arguments():
#     """Parse command line arguments"""
#     parser = argparse.ArgumentParser(description='Analyze Wireshark traffic for bot detection')
#     parser.add_argument('--csv', required=True, help='Path to CSV file converted from Wireshark PCAP')
#     parser.add_argument('--model', required=True, help='Path to saved model file (.joblib)')
#     parser.add_argument('--output', default='traffic_analysis_results.csv', help='Path to save results CSV')
#     parser.add_argument('--visualize', action='store_true', help='Generate visualization plots')
#     parser.add_argument('--verbose', action='store_true', help='Print detailed progress information')
#     parser.add_argument('--threshold', type=float, default=0.5, help='Threshold for bot classification (0.0-1.0)')
#     parser.add_argument('--min_flows', type=int, default=1, help='Minimum flow count threshold (default: 1)')
#     parser.add_argument('--debug', action='store_true', help='Print extensive debug information')
#     return parser.parse_args()

# def preprocess_wireshark_data(csv_file, verbose=False, debug=False):
#     """Preprocess the Wireshark CSV data to match model requirements"""
#     if verbose:
#         print(f"Loading data from {csv_file}...")

#     # Load the Wireshark CSV
#     try:
#         df = pd.read_csv(csv_file)
#     except Exception as e:
#         print(f"Error reading CSV file: {e}")
#         print("Please check that the file exists and is in CSV format.")
#         sys.exit(1)

#     if debug:
#         print(f"First 5 rows of input data:")
#         print(df.head())
    
#     if verbose:
#         print(f"Original data shape: {df.shape}")
#         print(f"Columns: {df.columns.tolist()}")

#     # Check if required columns exist and create if needed
#     required_columns = ['Proto', 'Dur', 'SrcAddr', 'DstAddr', 'TotPkts', 'TotBytes', 'SrcBytes', 'State']
#     missing_columns = [col for col in required_columns if col not in df.columns]
    
#     if missing_columns:
#         if verbose or debug:
#             print(f"Warning: Missing required columns: {missing_columns}")
#             print("Attempting to identify equivalent columns or create placeholders...")
        
#         # Try to map common alternative column names
#         column_alternatives = {
#             'Proto': ['Protocol', 'protocol', 'PROTO', 'proto'],
#             'Dur': ['Duration', 'duration', 'DUR', 'dur', 'Length', 'Time'],
#             'SrcAddr': ['Source', 'src', 'Src', 'Source Address', 'source', 'src_addr', 'src.addr'],
#             'DstAddr': ['Destination', 'dst', 'Dst', 'Destination Address', 'destination', 'dst_addr', 'dst.addr'],
#             'TotPkts': ['Packets', 'packets', 'pkt_count', 'packet_count', 'total_packets'],
#             'TotBytes': ['Bytes', 'bytes', 'byte_count', 'total_bytes', 'length'],
#             'SrcBytes': ['Source Bytes', 'src_bytes', 'orig_bytes'],
#             'State': ['Connection State', 'conn_state', 'state', 'Status', 'status']
#         }
        
#         for missing_col in missing_columns:
#             found = False
#             for alt in column_alternatives[missing_col]:
#                 if alt in df.columns:
#                     df[missing_col] = df[alt]
#                     if debug:
#                         print(f"Mapped '{alt}' to '{missing_col}'")
#                     found = True
#                     break
            
#             if not found:
#                 if debug:
#                     print(f"Creating placeholder for '{missing_col}'")
#                 # Create placeholder values
#                 if missing_col == 'Proto':
#                     df[missing_col] = 'tcp'  # Default to TCP
#                 elif missing_col == 'Dur':
#                     df[missing_col] = 1.0  # Default duration of 1 second
#                 elif missing_col == 'SrcAddr' and 'Source' in df.columns:
#                     df[missing_col] = df['Source']
#                 elif missing_col == 'DstAddr' and 'Destination' in df.columns:
#                     df[missing_col] = df['Destination']
#                 elif missing_col == 'TotPkts':
#                     df[missing_col] = 1  # Default to 1 packet
#                 elif missing_col == 'TotBytes':
#                     df[missing_col] = 100  # Default to 100 bytes
#                 elif missing_col == 'SrcBytes':
#                     df[missing_col] = 50  # Default to 50 bytes
#                 elif missing_col == 'State':
#                     df[missing_col] = 'CON'  # Default to connected state

#     # Map protocol names to match model expectations
#     proto_map = {
#         'TCP': 'tcp',
#         'UDP': 'udp',
#         'ICMP': 'icmp',
#         'tcp': 'tcp',
#         'udp': 'udp',
#         'icmp': 'icmp',
#         '6': 'tcp',  # TCP protocol number
#         '17': 'udp', # UDP protocol number
#         '1': 'icmp'  # ICMP protocol number
#     }

#     # Convert protocol names to lowercase and map to expected values
#     df['Proto'] = df['Proto'].map(lambda x: proto_map.get(str(x).upper(), 'tcp'))

#     if debug:
#         print(f"Protocol distribution after mapping:")
#         print(df['Proto'].value_counts())

#     # Map state values to expected values for our model
#     state_map = {
#         'EST': 'CON',         # Established connections map to CON (connected)
#         'FIN': 'FSPA_FSPA',   # Finished connections map to FSPA_FSPA
#         'SYN': 'CON',         # SYN connections map to CON
#         'RST': 'FSPA_FSPA',   # Reset connections map to FSPA_FSPA
#         'ECO': 'URP',         # ICMP Echo map to URP
#         'CON': 'CON',         # Keep CON as is
#         'ESTABLISHED': 'CON', # Common Wireshark status
#         'TIME_WAIT': 'FSPA_FSPA',
#         'FIN_WAIT': 'FSPA_FSPA',
#         'CLOSE_WAIT': 'FSPA_FSPA',
#         'CLOSED': 'FSPA_FSPA',
#         'RESET': 'FSPA_FSPA'
#     }

#     # Convert state names and apply mapping with fallback to 'CON'
#     df['State'] = df['State'].map(lambda x: state_map.get(str(x).upper(), 'CON'))

#     if debug:
#         print(f"State distribution after mapping:")
#         print(df['State'].value_counts())

#     # Ensure numeric columns are numeric
#     numeric_cols = ['Dur', 'TotPkts', 'TotBytes', 'SrcBytes']
#     for col in numeric_cols:
#         try:
#             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(1)
#         except Exception as e:
#             if debug:
#                 print(f"Error converting {col} to numeric: {e}")
#             df[col] = 1  # Default value

#     # Add StartTime if missing (using current time as placeholder)
#     if 'StartTime' not in df.columns:
#         base_time = datetime.now()
#         timestamps = [(base_time.replace(microsecond=0) - 
#                       pd.Timedelta(seconds=i)).strftime("%Y/%m/%d %H:%M:%S.%f") 
#                       for i in range(len(df), 0, -1)]
#         df['StartTime'] = timestamps

#     if verbose:
#         print(f"Preprocessed data shape: {df.shape}")
#         print(f"Columns after preprocessing: {df.columns.tolist()}")

#     if debug:
#         print(f"Sample of preprocessed data:")
#         print(df.head())

#     return df

# def build_graph_from_df(df, verbose=False, debug=False):
#     """Build network graph from traffic data"""
#     if verbose:
#         print("Building network graph...")

#     G = nx.Graph()
#     string_index = {}
#     edge_counter = 0

#     def get_index_node(text):
#         """Get index for a node, creating if necessary"""
#         if text not in string_index:
#             string_index[text] = len(string_index) + 1
#         return string_index[text]

#     # Map protocol to numeric values as per the training model
#     # Using numeric values to match training data
#     protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
    
#     # Direction mapping (matches the one-hot encoding in training)
#     direction_map = {
#         "->": 2,    # Corresponds to 'Dir_   ->'
#         "<->": 1,   # Corresponds to 'Dir_  <->'
#         "other": 0  # Corresponds to 'Dir_others'
#     }
    
#     for idx, row in df.iterrows():
#         try:
#             source = str(row['SrcAddr'])
#             destination = str(row['DstAddr'])
            
#             # Skip localhost or empty addresses
#             if source == destination or not source or not destination:
#                 if debug and idx < 10:  # Only show first 10 skipped entries to avoid spam
#                     print(f"Skipping row {idx}: src={source}, dst={destination} (same source/destination)")
#                 continue
                
#             # Handle various timestamp formats or create synthetic one
#             try:
#                 if 'StartTime' in row:
#                     try:
#                         start_time = datetime.strptime(str(row['StartTime']), "%Y/%m/%d %H:%M:%S.%f")
#                     except ValueError:
#                         try:
#                             start_time = datetime.strptime(str(row['StartTime']), "%Y-%m-%d %H:%M:%S.%f")
#                         except ValueError:
#                             start_time = datetime.now()
#                 else:
#                     start_time = datetime.now()
#             except (ValueError, KeyError):
#                 start_time = datetime.now()
            
#             # Get basic flow features
#             protocol = str(row['Proto']).lower()
#             duration = float(row['Dur'])
#             totalbytes = int(row['TotBytes'])
#             totalpackets = int(row['TotPkts'])
#             srcbytes = int(row['SrcBytes'])
            
#             # Map protocol to numeric values to match training data
#             protocol_num = protocol_map.get(protocol, 0)
            
#             # Determine direction based on srcbytes and totalbytes
#             if srcbytes > 0 and srcbytes < totalbytes:
#                 direction = "<->"  # Bidirectional
#                 dir_value = direction_map["<->"]
#             elif srcbytes == totalbytes:
#                 direction = "->"   # Unidirectional
#                 dir_value = direction_map["->"]
#             else:
#                 direction = "other"
#                 dir_value = direction_map["other"]
            
#             # Get or create node indices
#             src_index = get_index_node(source)
#             dst_index = get_index_node(destination)

#             if not G.has_node(src_index):
#                 G.add_node(src_index, host=source)

#             if not G.has_node(dst_index):
#                 G.add_node(dst_index, host=destination)

#             # Create edge features similar to those used in training
#             if G.has_edge(src_index, dst_index):
#                 edge = G[src_index][dst_index]
#                 edge['flows'].append({
#                     'Dur': duration,
#                     'TotPkts': totalpackets,
#                     'TotBytes': totalbytes,
#                     'SrcBytes': srcbytes,
#                     'Proto': protocol_num,
#                     'Dir': dir_value,
#                     'sTos': 0,  # Default value for Type of Service, could be enhanced
#                     'dTos': 0,  # Default value for Type of Service, could be enhanced
#                     'Periodicity': (start_time - edge['periodicity']).total_seconds() if 'periodicity' in edge else 0
#                 })
#                 edge['periodicity'] = start_time
#                 edge_counter += 1
#             else:
#                 G.add_edge(src_index, dst_index)
#                 G[src_index][dst_index]['flows'] = [{
#                     'Dur': duration,
#                     'TotPkts': totalpackets,
#                     'TotBytes': totalbytes,
#                     'SrcBytes': srcbytes,
#                     'Proto': protocol_num,
#                     'Dir': dir_value,
#                     'sTos': 0,  # Default value for Type of Service
#                     'dTos': 0,  # Default value for Type of Service
#                     'Periodicity': 0
#                 }]
#                 G[src_index][dst_index]['periodicity'] = start_time
#                 edge_counter += 1
                
#         except Exception as e:
#             if verbose or (debug and idx < 10):  # Limit debug output
#                 print(f"Error processing row {idx}: {e}")
#             continue

#     if verbose:
#         print(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
#         print(f"Total flow entries: {edge_counter}")

#     if debug and G.number_of_edges() > 0:
#         print("\nSample edge data:")
#         for u, v, d in list(G.edges(data=True))[:3]:  # Show first 3 edges
#             print(f"Edge {G.nodes[u]['host']} -> {G.nodes[v]['host']}")
#             print(f"  Flow entries: {len(d['flows'])}")
#             if len(d['flows']) > 0:
#                 print(f"  Sample entry: {d['flows'][0]}")

#     return G

# def extract_features_from_graph(G, verbose=False, debug=False, min_flows=1):
#     """Extract features from graph edges that match the training model's expectations"""
#     if verbose:
#         print("Extracting features from graph...")

#     X = []
#     edge_info = []  # Store edge information for results analysis
#     total_edges = 0
#     filtered_edges = 0

#     # Reduced feature set to match the 10 features expected by the model
#     # The features must be in the same order as they were during training
#     for u, v, data in G.edges(data=True):
#         flows = data.get('flows', [])
        
#         if len(flows) <= min_flows:
#             filtered_edges += 1
#             continue
            
#         # Store source and destination for this edge
#         source_host = G.nodes[u].get('host', f"Node_{u}")
#         dest_host = G.nodes[v].get('host', f"Node_{v}")
#         edge_info.append((source_host, dest_host))
        
#         total_edges += 1
        
#         # Calculate average values for numeric features
#         avg_dur = np.mean([flow['Dur'] for flow in flows])
#         avg_totpkts = np.mean([flow['TotPkts'] for flow in flows])
#         avg_totbytes = np.mean([flow['TotBytes'] for flow in flows])
#         avg_srcbytes = np.mean([flow['SrcBytes'] for flow in flows])
        
#         # Determine most common protocol and direction
#         proto_counts = {}
#         dir_counts = {}
        
#         for flow in flows:
#             proto = flow['Proto'] 
#             if proto in proto_counts:
#                 proto_counts[proto] += 1
#             else:
#                 proto_counts[proto] = 1
                
#             direction = flow['Dir']
#             if direction in dir_counts:
#                 dir_counts[direction] += 1
#             else:
#                 dir_counts[direction] = 1
        
#         # Simplified feature set to match the 10 expected features
#         # The most important features based on common botnet detection models:
#         # 1. Duration
#         # 2. Total Packets
#         # 3. Total Bytes
#         # 4. Source Bytes
#         # 5-7. One-hot for protocol (TCP, UDP, other)
#         # 8-10. One-hot for direction (uni, bi, other)
        
#         # Convert to simplified one-hot for protocol (3 features)
#         proto_tcp = 1 if 6 in proto_counts else 0
#         proto_udp = 1 if 17 in proto_counts else 0
#         proto_other = 1 if any(p not in [6, 17] for p in proto_counts) else 0
        
#         # Convert to simplified one-hot for direction (3 features)
#         dir_arrow = 1 if 2 in dir_counts else 0  # Unidirectional
#         dir_bidir = 1 if 1 in dir_counts else 0  # Bidirectional
#         dir_other = 1 if 0 in dir_counts else 0  # Other
        
#         # Create 10-feature vector matching the expected model inputs
#         features = [
#             avg_dur, 
#             avg_totpkts, 
#             avg_totbytes, 
#             avg_srcbytes,
#             proto_tcp, 
#             proto_udp, 
#             proto_other,
#             dir_arrow, 
#             dir_bidir, 
#             dir_other
#         ]
        
#         X.append(features)
        
#         if debug and total_edges <= 3:  # Show details for first 3 valid edges
#             print(f"Edge {source_host} -> {dest_host}: {len(flows)} flows")
#             print(f"  Features: {features}")

#     if verbose:
#         print(f"Filtered out {filtered_edges} edges below flow threshold")
#         print(f"Extracted features for {total_edges} connections")

#     # Create DataFrame with the expected columns
#     column_list = [
#         'Dur', 'TotPkts', 'TotBytes', 'SrcBytes',
#         'Proto_tcp', 'Proto_udp', 'Proto_other',
#         'Dir_uni', 'Dir_bi', 'Dir_other'
#     ]
    
#     X_df = pd.DataFrame(X, columns=column_list) if X else pd.DataFrame(columns=column_list)
    
#     if debug:
#         print(f"Feature DataFrame shape: {X_df.shape}")
#         if not X_df.empty:
#             print(f"Feature columns: {X_df.columns.tolist()}")
#             print(f"Sample features:\n{X_df.head()}")

#     return X_df, edge_info

# def predict_traffic(model, X, edge_info, threshold=0.5, verbose=False, debug=False):
#     """Make predictions using the joblib model"""
#     if X.empty:
#         if verbose:
#             print("No valid connections to predict")
#         return pd.DataFrame()

#     if verbose:
#         print("Making predictions...")

#     # Get model predictions
#     try:
#         # If the model is a classifier (like RandomForest, DecisionTree, etc.)
#         if hasattr(model, 'predict_proba'):
#             # Get probabilities
#             proba = model.predict_proba(X)
#             # Botnet probability is the probability of class 1
#             if proba.shape[1] >= 2:  # Ensure we have at least two classes
#                 if debug:
#                     print(f"Classes: {model.classes_}")
#                 # Find index of class 1 (botnet)
#                 bot_idx = np.where(model.classes_ == 1)[0]
#                 if len(bot_idx) > 0:
#                     bot_probs = proba[:, bot_idx[0]]
#                 else:
#                     # Default to second class if 1 is not explicitly labeled
#                     bot_probs = proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
#             else:
#                 bot_probs = proba[:, 0]
                
#             # Direct predictions
#             predictions = model.predict(X)
            
#             if debug:
#                 print(f"Prediction classes: {np.unique(predictions)}")
#                 print(f"Sample probabilities: {proba[:5]}")
#         else:
#             # For models that only give class output
#             predictions = model.predict(X)
#             # Fake probabilities (just 0 or 1)
#             bot_probs = (predictions == 1).astype(float)
    
#     except Exception as e:
#         print(f"Error during prediction: {e}")
#         print("Falling back to direct predictions only")
#         predictions = model.predict(X)
#         bot_probs = (predictions == 1).astype(float)
    
#     # Map numeric predictions to labels: 1 = Botnet, 2 = Normal, 0 = Other
#     label_map = {
#         0: "Other",
#         1: "Bot",
#         2: "Normal"
#     }
    
#     # Create a DataFrame with results
#     results = pd.DataFrame({
#         'Source': [src for src, _ in edge_info],
#         'Destination': [dst for _, dst in edge_info],
#         'Bot_Probability': bot_probs,
#         'Prediction_Class': predictions,
#         'Classification': [label_map.get(int(p), "Unknown") for p in predictions]
#     })

#     if debug:
#         print(f"Results shape: {results.shape}")
#         print(f"Sample results:\n{results.head()}")

#     return results

# def visualize_results(results_df, output_prefix="", verbose=False):
#     """Generate visualizations of the detection results"""
#     if results_df.empty:
#         if verbose:
#             print("No results to visualize")
#         return

#     if verbose:
#         print("Generating visualizations...")

#     # Create output directory if it doesn't exist
#     os.makedirs("visualizations", exist_ok=True)

#     # Plot distribution of predictions by class
#     plt.figure(figsize=(10, 6))
#     results_df['Classification'].value_counts().plot(kind='bar')
#     plt.title('Distribution of Traffic Classifications')
#     plt.xlabel('Classification')
#     plt.ylabel('Count')
#     plt.tight_layout()
#     plt.savefig(f"visualizations/{output_prefix}classification_distribution.png")

#     # Create pie chart of classifications
#     plt.figure(figsize=(8, 8))
#     results_df['Classification'].value_counts().plot(kind='pie', autopct='%1.1f%%')
#     plt.axis('equal')
#     plt.title('Traffic Classification Results')
#     plt.tight_layout()
#     plt.savefig(f"visualizations/{output_prefix}traffic_classification_pie.png")

#     # Show top IPs involved in suspicious traffic
#     bot_traffic = results_df[results_df['Classification'] == 'Bot']
#     if not bot_traffic.empty:
#         # Top source IPs
#         top_sources = bot_traffic['Source'].value_counts().head(10)
#         plt.figure(figsize=(12, 6))
#         top_sources.plot(kind='bar')
#         plt.title('Top Source IPs in Bot Traffic')
#         plt.xlabel('Source IP')
#         plt.ylabel('Number of Bot Connections')
#         plt.tight_layout()
#         plt.savefig(f"visualizations/{output_prefix}top_bot_sources.png")
        
#         # Top destination IPs
#         top_destinations = bot_traffic['Destination'].value_counts().head(10)
#         plt.figure(figsize=(12, 6))
#         top_destinations.plot(kind='bar')
#         plt.title('Top Destination IPs in Bot Traffic')
#         plt.xlabel('Destination IP')
#         plt.ylabel('Number of Bot Connections')
#         plt.tight_layout()
#         plt.savefig(f"visualizations/{output_prefix}top_bot_destinations.png")

#     if verbose:
#         print(f"Visualizations saved to visualizations/ directory")

# def print_summary(results_df):
#     """Print a summary of the analysis results with improved formatting"""
#     if results_df.empty:
#         print("\n" + "=" * 60)
#         print("                    ANALYSIS SUMMARY                      ")
#         print("=" * 60)
#         print("No valid connections were found for analysis")
#         return

#     total_connections = len(results_df)
    
#     # Count by classification
#     class_counts = results_df['Classification'].value_counts()
#     bot_connections = class_counts.get('Bot', 0)
#     normal_connections = class_counts.get('Normal', 0)
#     other_connections = class_counts.get('Other', 0)
    
#     # Create a colorful banner
#     print("\n" + "=" * 60)
#     print("               TRAFFIC ANALYSIS SUMMARY                 ")
#     print("=" * 60)
    
#     # Print general statistics
#     summary_table = [
#         ["Total Connections Analyzed", f"{total_connections}"],
#         ["Bot Traffic Detected", f"{bot_connections} ({bot_connections/total_connections*100:.2f}%)"],
#         ["Normal Traffic Detected", f"{normal_connections} ({normal_connections/total_connections*100:.2f}%)"],
#         ["Other Traffic Detected", f"{other_connections} ({other_connections/total_connections*100:.2f}%)"]
#     ]
#     print(tabulate(summary_table, tablefmt="simple"))
    
#     # Get top suspicious IPs (those involved in bot traffic)
#     if bot_connections > 0:
#         bot_traffic = results_df[results_df['Classification'] == 'Bot']
        
#         # Count occurrences of each IP in bot traffic (source and destination)
#         source_counts = bot_traffic['Source'].value_counts().head(5)
#         dest_counts = bot_traffic['Destination'].value_counts().head(5)
        
#         print("\n" + "=" * 60)
#         print("                TOP SUSPICIOUS IPs                  ")
#         print("=" * 60)
        
#         if not source_counts.empty:
#             print("Top Source IPs in Bot Traffic:")
#             source_table = [(ip, count, f"{count/bot_connections*100:.1f}%") 
#                            for ip, count in source_counts.items()]
#             print(tabulate(source_table, headers=["IP Address", "Bot Connections", "% of Bot Traffic"], 
#                           tablefmt="simple"))
        
#         if not dest_counts.empty:
#             print("\nTop Destination IPs in Bot Traffic:")
#             dest_table = [(ip, count, f"{count/bot_connections*100:.1f}%") 
#                          for ip, count in dest_counts.items()]
#             print(tabulate(dest_table, headers=["IP Address", "Bot Connections", "% of Bot Traffic"], 
#                           tablefmt="simple"))

# def print_detailed_results(results_df, top_n=10):
#     """Print detailed analysis results for top suspicious connections"""
#     if results_df.empty:
#         return
        
#     # Get bot traffic
#     bot_traffic = results_df[results_df['Classification'] == 'Bot']
    
#     if bot_traffic.empty:
#         print("\nNo bot traffic detected.")
#         return
    
#     # Sort by bot probability (highest first)
#     sorted_results = bot_traffic.sort_values('Bot_Probability', ascending=False)
    
#     # Get top suspicious connections
#     top_suspicious = sorted_results.head(top_n)
    
#     print("\n" + "=" * 70)
#     print("                  TOP SUSPICIOUS CONNECTIONS                    ")
#     print("=" * 70)
    
#     # Format the data for tabulate
#     table_data = []
#     for _, row in top_suspicious.iterrows():
#         table_data.append([
#             row['Source'], 
#             row['Destination'], 
#             f"{row['Bot_Probability']:.4f}", 
#             row['Classification']
#         ])
    
#     print(tabulate(table_data, 
#                   headers=["Source IP", "Destination IP", "Bot Probability", "Classification"],
#                   tablefmt="simple"))

# def examine_csv_file(csv_file):
#     """Examine CSV file and print a summary of its contents"""
#     print("\n" + "=" * 70)
#     print("                      CSV FILE SUMMARY                        ")
#     print("=" * 70)
    
#     try:
#         df = pd.read_csv(csv_file)
#         print(f"File: {csv_file}")
#         print(f"Total rows: {len(df)}")
#         print(f"Columns found: {', '.join(df.columns.tolist())}")
        
#         # Check for common expected columns
#         common_columns = ['Proto', 'Dur', 'SrcAddr', 'DstAddr', 'TotPkts', 'TotBytes', 'SrcBytes', 'State']
#         missing = [col for col in common_columns if col not in df.columns]
#         if missing:
#             print(f"Missing expected columns: {', '.join(missing)}")
            
#             # Try to identify potential substitute columns
#             potential_replacements = {}
#             for col in missing:
#                 if col == 'Proto':
#                     candidates = [c for c in df.columns if 'proto' in c.lower() or 'protocol' in c.lower()]
#                 elif col == 'Dur':
#                     candidates = [c for c in df.columns if 'dur' in c.lower() or 'time' in c.lower() or 'length' in c.lower()]
#                 elif col == 'SrcAddr':
#                     candidates = [c for c in df.columns if 'src' in c.lower() or 'source' in c.lower()]
#                 elif col == 'DstAddr':
#                     candidates = [c for c in df.columns if 'dst' in c.lower() or 'dest' in c.lower()]
#                 elif col == 'TotPkts':
#                     candidates = [c for c in df.columns if 'pkt' in c.lower() or 'packet' in c.lower()]
#                 elif col == 'TotBytes':
#                     candidates = [c for c in df.columns if 'byte' in c.lower() or 'size' in c.lower()]
#                 elif col == 'SrcBytes':
#                     candidates = [c for c in df.columns if 'src' in c.lower() and ('byte' in c.lower() or 'size' in c.lower())]
#                 elif col == 'State':
#                     candidates = [c for c in df.columns if 'state' in c.lower() or 'status' in c.lower() or 'flag' in c.lower()]
#                 else:
#                     candidates = []
                    
#                 if candidates:
#                     potential_replacements[col] = candidates
            
#             if potential_replacements:
#                 print("\nPotential column replacements:")
#                 for col, candidates in potential_replacements.items():
#                     print(f"  {col} -> {', '.join(candidates)}")
        
#         # Print a sample of the data
#         print("\nSample data (first 3 rows):")
#         sample_df = df.head(3)
#         print(tabulate(sample_df.to_dict('records'), headers="keys", tablefmt="simple"))
        
#     except Exception as e:
#         print(f"Error examining CSV file: {e}")
#         print("Please check that the file exists and is in valid CSV format.")

# def examine_model(model_file, verbose=False):
#     """Examine the model to understand its expected features"""
#     try:
#         model = joblib.load(model_file)
        
#         print("\n" + "=" * 60)
#         print("                    MODEL INFORMATION                      ")
#         print("=" * 60)
        
#         print(f"Model type: {type(model).__name__}")
        
#         # Check if it's a scikit-learn model with feature names
#         if hasattr(model, 'feature_names_in_'):
#             print(f"Expected features ({len(model.feature_names_in_)}):")
#             for i, feature in enumerate(model.feature_names_in_):
#                 print(f"  {i+1}. {feature}")
#         # Check if it's a scikit-learn model with n_features_in_ attribute
#         elif hasattr(model, 'n_features_in_'):
#             print(f"Expected number of features: {model.n_features_in_}")
#         else:
#             print("Could not determine expected number of features from model.")
            
#         # Check for classes if it's a classifier
#         if hasattr(model, 'classes_'):
#             print(f"Model classes: {model.classes_}")
            
#         # If it's a RandomForest, show feature importance
#         if hasattr(model, 'feature_importances_'):
#             print("\nFeature importances:")
#             if hasattr(model, 'feature_names_in_'):
#                 importances = [(name, imp) for name, imp in zip(model.feature_names_in_, model.feature_importances_)]
#                 importances.sort(key=lambda x: x[1], reverse=True)
#                 for name, imp in importances:
#                     print(f"  {name}: {imp:.4f}")
#             else:
#                 importances = [(i, imp) for i, imp in enumerate(model.feature_importances_)]
#                 importances.sort(key=lambda x: x[1], reverse=True)
#                 for i, imp in importances:
#                     print(f"  Feature {i}: {imp:.4f}")
                    
#     except Exception as e:
#         print(f"Error examining model: {e}")
#         print("Unable to extract model information.")

# def main():
#     """Main function for the script"""
#     args = parse_arguments()
    
#     # Print welcome message
#     print("\n" + "#" * 70)
#     print("##  Wireshark Traffic Bot Detection Tool  ##")
#     print("#" * 70)
    
#     # Examine model first to understand what features it expects
#     if args.debug or args.verbose:
#         examine_model(args.model, verbose=args.verbose)
    
#     # Examine input CSV file
#     if args.debug or args.verbose:
#         examine_csv_file(args.csv)
        
#     # Load the model
#     if args.verbose:
#         print(f"\nLoading model from {args.model}...")
    
#     try:
#         model = joblib.load(args.model)
#         if args.verbose:
#             print(f"Model loaded successfully: {type(model).__name__}")
#             if hasattr(model, 'n_features_in_'):
#                 print(f"Model expects {model.n_features_in_} input features")

#     except Exception as e:
#         print(f"Error loading model: {e}")
#         print("Please check that the model file exists and is a valid joblib file.")
#         sys.exit(1)
    
#     # Preprocess the input data
#     processed_df = preprocess_wireshark_data(args.csv, verbose=args.verbose, debug=args.debug)
    
#     # Build network graph
#     graph = build_graph_from_df(processed_df, verbose=args.verbose, debug=args.debug)
    
#     # Extract featuresa
#     features_df, edge_info = extract_features_from_graph(graph, verbose=args.verbose, 
#                                                         debug=args.debug, min_flows=args.min_flows)
    
#     if features_df.empty:
#         print("\nNo valid connections for analysis. Please check your data or lower the min_flows threshold.")
#         sys.exit(0)
        
#     if args.debug:
#         print(f"\nGenerated features shape: {features_df.shape}")
#         print(f"Feature columns: {features_df.columns.tolist()}")
    
#     # Check if features match what the model expects
#     if hasattr(model, 'n_features_in_') and features_df.shape[1] != model.n_features_in_:
#         print(f"\nWARNING: Feature mismatch! Model expects {model.n_features_in_} features, but generated {features_df.shape[1]} features.")
#         if args.debug:
#             print("This usually means the model was trained on different features than what this script generates.")
#             print("To fix, either:")
#             print("1. Use a model trained with the same feature set")
#             print("2. Modify the extract_features_from_graph function to match the model's expectations")
#         sys.exit(1)
    
#     # Make predictions
#     try:
#         results = predict_traffic(model, features_df, edge_info, threshold=args.threshold, 
#                                 verbose=args.verbose, debug=args.debug)
    
#         # Save results to CSV
#         if not results.empty:
#             results.to_csv(args.output, index=False)
#             if args.verbose:
#                 print(f"Results saved to {args.output}")
#         else:
#             if args.verbose:
#                 print("No results to save")
        
#         # Generate visualizations if requested
#         if args.visualize:
#             output_prefix = os.path.splitext(os.path.basename(args.csv))[0] + "_"
#             visualize_results(results, output_prefix=output_prefix, verbose=args.verbose)
        
#         # Print summary results
#         print_summary(results)
#         if not results.empty and args.verbose:
#             print_detailed_results(results)
        
#     except Exception as e:
#         print(f"\nError during analysis: {e}")
#         import traceback
#         if args.debug:
#             print("\nDetailed error information:")
#             traceback.print_exc()
#         print("\nAnalysis failed. Please check your input data and model compatibility.")
#         sys.exit(1)
    
#     print("\nAnalysis complete.")

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
Wireshark Traffic Bot Detection Tool (Updated for .joblib ML Models)

This script analyzes CSV data converted from Wireshark PCAP files
to detect bot traffic using a pre-trained machine learning model.

Usage:
python detect_bot_traffic.py --csv wireshark_data.csv --model model_file.joblib --output results.csv
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import joblib
import networkx as nx
from datetime import datetime
import matplotlib.pyplot as plt
from tabulate import tabulate  # For better terminal visualization

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Analyze Wireshark traffic for bot detection')
    parser.add_argument('--csv', required=True, help='Path to CSV file converted from Wireshark PCAP')
    parser.add_argument('--model', required=True, help='Path to saved model file (.joblib)')
    parser.add_argument('--output', default='traffic_analysis_results.csv', help='Path to save results CSV')
    parser.add_argument('--visualize', action='store_true', help='Generate visualization plots')
    parser.add_argument('--verbose', action='store_true', help='Print detailed progress information')
    parser.add_argument('--threshold', type=float, default=0.5, help='Threshold for bot classification (0.0-1.0)')
    parser.add_argument('--min_flows', type=int, default=1, help='Minimum flow count threshold (default: 1)')
    parser.add_argument('--debug', action='store_true', help='Print extensive debug information')
    parser.add_argument('--include_localhost', action='store_true', help='Include localhost traffic (127.0.0.1)')
    return parser.parse_args()

def preprocess_wireshark_data(csv_file, verbose=False, debug=False):
    """Preprocess the Wireshark CSV data to match model requirements"""
    if verbose:
        print(f"Loading data from {csv_file}...")

    # Load the Wireshark CSV
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        print("Please check that the file exists and is in CSV format.")
        sys.exit(1)

    if debug:
        print(f"First 5 rows of input data:")
        print(df.head())
    
    if verbose:
        print(f"Original data shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")

    # Check if required columns exist and create if needed
    required_columns = ['Proto', 'Dur', 'SrcAddr', 'DstAddr', 'TotPkts', 'TotBytes', 'SrcBytes', 'State']
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        if verbose or debug:
            print(f"Warning: Missing required columns: {missing_columns}")
            print("Attempting to identify equivalent columns or create placeholders...")
        
        # Try to map common alternative column names
        column_alternatives = {
            'Proto': ['Protocol', 'protocol', 'PROTO', 'proto'],
            'Dur': ['Duration', 'duration', 'DUR', 'dur', 'Length', 'Time'],
            'SrcAddr': ['Source', 'src', 'Src', 'Source Address', 'source', 'src_addr', 'src.addr'],
            'DstAddr': ['Destination', 'dst', 'Dst', 'Destination Address', 'destination', 'dst_addr', 'dst.addr'],
            'TotPkts': ['Packets', 'packets', 'pkt_count', 'packet_count', 'total_packets'],
            'TotBytes': ['Bytes', 'bytes', 'byte_count', 'total_bytes', 'length'],
            'SrcBytes': ['Source Bytes', 'src_bytes', 'orig_bytes'],
            'State': ['Connection State', 'conn_state', 'state', 'Status', 'status']
        }
        
        for missing_col in missing_columns:
            found = False
            for alt in column_alternatives[missing_col]:
                if alt in df.columns:
                    df[missing_col] = df[alt]
                    if debug:
                        print(f"Mapped '{alt}' to '{missing_col}'")
                    found = True
                    break
            
            if not found:
                if debug:
                    print(f"Creating placeholder for '{missing_col}'")
                # Create placeholder values
                if missing_col == 'Proto':
                    df[missing_col] = 'tcp'  # Default to TCP
                elif missing_col == 'Dur':
                    df[missing_col] = 1.0  # Default duration of 1 second
                elif missing_col == 'SrcAddr' and 'Source' in df.columns:
                    df[missing_col] = df['Source']
                elif missing_col == 'DstAddr' and 'Destination' in df.columns:
                    df[missing_col] = df['Destination']
                elif missing_col == 'TotPkts':
                    df[missing_col] = 1  # Default to 1 packet
                elif missing_col == 'TotBytes':
                    df[missing_col] = 100  # Default to 100 bytes
                elif missing_col == 'SrcBytes':
                    df[missing_col] = 50  # Default to 50 bytes
                elif missing_col == 'State':
                    df[missing_col] = 'CON'  # Default to connected state

    # Map protocol names to match model expectations
    proto_map = {
        'TCP': 'tcp',
        'UDP': 'udp',
        'ICMP': 'icmp',
        'tcp': 'tcp',
        'udp': 'udp',
        'icmp': 'icmp',
        '6': 'tcp',  # TCP protocol number
        '17': 'udp', # UDP protocol number
        '1': 'icmp'  # ICMP protocol number
    }

    # Convert protocol names to lowercase and map to expected values
    df['Proto'] = df['Proto'].map(lambda x: proto_map.get(str(x).upper(), 'tcp'))

    if debug:
        print(f"Protocol distribution after mapping:")
        print(df['Proto'].value_counts())

    # Map state values to expected values for our model
    state_map = {
        'EST': 'CON',         # Established connections map to CON (connected)
        'FIN': 'FSPA_FSPA',   # Finished connections map to FSPA_FSPA
        'SYN': 'CON',         # SYN connections map to CON
        'RST': 'FSPA_FSPA',   # Reset connections map to FSPA_FSPA
        'ECO': 'URP',         # ICMP Echo map to URP
        'CON': 'CON',         # Keep CON as is
        'ESTABLISHED': 'CON', # Common Wireshark status
        'TIME_WAIT': 'FSPA_FSPA',
        'FIN_WAIT': 'FSPA_FSPA',
        'CLOSE_WAIT': 'FSPA_FSPA',
        'CLOSED': 'FSPA_FSPA',
        'RESET': 'FSPA_FSPA'
    }

    # Convert state names and apply mapping with fallback to 'CON'
    df['State'] = df['State'].map(lambda x: state_map.get(str(x).upper(), 'CON'))

    if debug:
        print(f"State distribution after mapping:")
        print(df['State'].value_counts())

    # Ensure numeric columns are numeric
    numeric_cols = ['Dur', 'TotPkts', 'TotBytes', 'SrcBytes']
    for col in numeric_cols:
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(1)
        except Exception as e:
            if debug:
                print(f"Error converting {col} to numeric: {e}")
            df[col] = 1  # Default value

    # Add StartTime if missing (using current time as placeholder)
    if 'StartTime' not in df.columns:
        base_time = datetime.now()
        timestamps = [(base_time.replace(microsecond=0) - 
                      pd.Timedelta(seconds=i)).strftime("%Y/%m/%d %H:%M:%S.%f") 
                      for i in range(len(df), 0, -1)]
        df['StartTime'] = timestamps

    if verbose:
        print(f"Preprocessed data shape: {df.shape}")
        print(f"Columns after preprocessing: {df.columns.tolist()}")

    if debug:
        print(f"Sample of preprocessed data:")
        print(df.head())

    return df

def build_graph_from_df(df, verbose=False, debug=False, include_localhost=True):
    """Build network graph from traffic data"""
    if verbose:
        print("Building network graph...")

    G = nx.Graph()
    string_index = {}
    edge_counter = 0
    include_same_src_dst = include_localhost  # Use flag to decide if we should include localhost connections

    def get_index_node(text):
        """Get index for a node, creating if necessary"""
        if text not in string_index:
            string_index[text] = len(string_index) + 1
        return string_index[text]

    # Map protocol to numeric values as per the training model
    # Using numeric values to match training data
    protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
    
    # Direction mapping (matches the one-hot encoding in training)
    direction_map = {
        "->": 2,    # Corresponds to 'Dir_   ->'
        "<->": 1,   # Corresponds to 'Dir_  <->'
        "other": 0  # Corresponds to 'Dir_others'
    }
    
    for idx, row in df.iterrows():
        try:
            source = str(row['SrcAddr'])
            destination = str(row['DstAddr'])
            
            # Skip empty addresses
            if not source or not destination:
                if debug and idx < 10:  # Only show first 10 skipped entries to avoid spam
                    print(f"Skipping row {idx}: src={source}, dst={destination} (empty address)")
                continue
            
            # Skip localhost traffic unless explicitly allowed
            if source == destination and not include_same_src_dst:
                if debug and idx < 10:  # Only show first 10 skipped entries to avoid spam
                    print(f"Skipping row {idx}: src={source}, dst={destination} (same source/destination)")
                continue
                
            # Handle various timestamp formats or create synthetic one
            try:
                if 'StartTime' in row:
                    try:
                        start_time = datetime.strptime(str(row['StartTime']), "%Y/%m/%d %H:%M:%S.%f")
                    except ValueError:
                        try:
                            start_time = datetime.strptime(str(row['StartTime']), "%Y-%m-%d %H:%M:%S.%f")
                        except ValueError:
                            start_time = datetime.now()
                else:
                    start_time = datetime.now()
            except (ValueError, KeyError):
                start_time = datetime.now()
            
            # Get basic flow features
            protocol = str(row['Proto']).lower()
            duration = float(row['Dur'])
            totalbytes = int(row['TotBytes'])
            totalpackets = int(row['TotPkts'])
            srcbytes = int(row['SrcBytes'])
            
            # Add port information if available
            src_port = int(row.get('SrcPort', 0)) if pd.notna(row.get('SrcPort', 0)) else 0
            dst_port = int(row.get('DstPort', 0)) if pd.notna(row.get('DstPort', 0)) else 0
            
            # Map protocol to numeric values to match training data
            protocol_num = protocol_map.get(protocol, 0)
            
            # Determine direction based on srcbytes and totalbytes
            if srcbytes > 0 and srcbytes < totalbytes:
                direction = "<->"  # Bidirectional
                dir_value = direction_map["<->"]
            elif srcbytes == totalbytes:
                direction = "->"   # Unidirectional
                dir_value = direction_map["->"]
            else:
                direction = "other"
                dir_value = direction_map["other"]
            
            # Include port information in node identification for better granularity
            # This helps distinguish different services on the same IP
            if src_port > 0 and dst_port > 0:
                source_node = f"{source}:{src_port}"
                dest_node = f"{destination}:{dst_port}"
            else:
                source_node = source
                dest_node = destination
            
            # Get or create node indices
            src_index = get_index_node(source_node)
            dst_index = get_index_node(dest_node)

            if not G.has_node(src_index):
                G.add_node(src_index, host=source, port=src_port)

            if not G.has_node(dst_index):
                G.add_node(dst_index, host=destination, port=dst_port)

            # Create or update the edge
            flow_entry = {
                'Dur': duration,
                'TotPkts': totalpackets,
                'TotBytes': totalbytes,
                'SrcBytes': srcbytes,
                'Proto': protocol_num,
                'Dir': dir_value,
                'sTos': 0,  # Default value for Type of Service
                'dTos': 0,  # Default value for Type of Service
                'Periodicity': 0,  # Will update if this is not the first flow
                'SrcPort': src_port,
                'DstPort': dst_port
            }
            
            if G.has_edge(src_index, dst_index):
                edge = G[src_index][dst_index]
                
                # Calculate periodicity if there's a previous timestamp
                if 'periodicity' in edge:
                    flow_entry['Periodicity'] = (start_time - edge['periodicity']).total_seconds()
                
                edge['flows'].append(flow_entry)
                edge['periodicity'] = start_time
                edge_counter += 1
            else:
                G.add_edge(src_index, dst_index)
                G[src_index][dst_index]['flows'] = [flow_entry]
                G[src_index][dst_index]['periodicity'] = start_time
                edge_counter += 1
                
        except Exception as e:
            if verbose or (debug and idx < 10):  # Limit debug output
                print(f"Error processing row {idx}: {e}")
            continue

    if verbose:
        print(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
        print(f"Total flow entries: {edge_counter}")

    if debug and G.number_of_edges() > 0:
        print("\nSample edge data:")
        for u, v, d in list(G.edges(data=True))[:3]:  # Show first 3 edges
            print(f"Edge {G.nodes[u].get('host', 'Unknown')}:{G.nodes[u].get('port', 0)} -> "
                  f"{G.nodes[v].get('host', 'Unknown')}:{G.nodes[v].get('port', 0)}")
            print(f"  Flow entries: {len(d['flows'])}")
            if len(d['flows']) > 0:
                print(f"  Sample entry: {d['flows'][0]}")

    return G

def aggregate_flows_by_ip(G, verbose=False, debug=False):
    """Aggregate flows at the IP level, ignoring ports"""
    if verbose:
        print("Aggregating flows at IP level...")
    
    # Create a new graph for IP-level aggregation
    IP_G = nx.Graph()
    
    # Map to track aggregation
    ip_nodes = {}
    
    # Identify unique IPs and add to new graph
    for node, data in G.nodes(data=True):
        ip = data.get('host', 'unknown')
        
        if ip not in ip_nodes:
            # First time seeing this IP, create new node
            ip_nodes[ip] = len(ip_nodes) + 1
            IP_G.add_node(ip_nodes[ip], host=ip)
    
    # Aggregate flows between IPs
    for u, v, edge_data in G.edges(data=True):
        src_ip = G.nodes[u].get('host', 'unknown')
        dst_ip = G.nodes[v].get('host', 'unknown')
        
        src_idx = ip_nodes[src_ip]
        dst_idx = ip_nodes[dst_ip]
        
        # Skip self-loops unless the original edge wasn't a self-loop
        if src_idx == dst_idx and u != v:
            continue
        
        # Add or update edge
        if IP_G.has_edge(src_idx, dst_idx):
            # Append flows from the original edge
            IP_G[src_idx][dst_idx]['flows'].extend(edge_data.get('flows', []))
        else:
            # Create new edge with flows from the original edge
            IP_G.add_edge(src_idx, dst_idx)
            IP_G[src_idx][dst_idx]['flows'] = edge_data.get('flows', [])[:]  # Create a copy
    
    if verbose:
        print(f"Aggregated graph has {IP_G.number_of_nodes()} nodes and {IP_G.number_of_edges()} edges")
    
    if debug and IP_G.number_of_edges() > 0:
        # Show sample of aggregated edges
        print("\nSample aggregated edge data:")
        for u, v, d in list(IP_G.edges(data=True))[:3]:
            print(f"Edge {IP_G.nodes[u].get('host', 'Unknown')} -> {IP_G.nodes[v].get('host', 'Unknown')}")
            print(f"  Aggregated flow entries: {len(d['flows'])}")
    
    return IP_G

def extract_features_from_graph(G, verbose=False, debug=False, min_flows=1):
    """Extract features from graph edges that match the training model's expectations"""
    if verbose:
        print("Extracting features from graph...")

    X = []
    edge_info = []  # Store edge information for results analysis
    total_edges = 0
    filtered_edges = 0

    # Reduced feature set to match the 10 features expected by the model
    # The features must be in the same order as they were during training
    for u, v, data in G.edges(data=True):
        flows = data.get('flows', [])
        
        # Skip edges with too few flows 
        if len(flows) < min_flows:
            filtered_edges += 1
            continue
            
        # Store source and destination for this edge
        source_host = G.nodes[u].get('host', f"Node_{u}")
        dest_host = G.nodes[v].get('host', f"Node_{v}")
        edge_info.append((source_host, dest_host))
        
        total_edges += 1
        
        # Calculate average values for numeric features
        avg_dur = np.mean([flow['Dur'] for flow in flows])
        avg_totpkts = np.mean([flow['TotPkts'] for flow in flows])
        avg_totbytes = np.mean([flow['TotBytes'] for flow in flows])
        avg_srcbytes = np.mean([flow['SrcBytes'] for flow in flows])
        
        # Determine most common protocol and direction
        proto_counts = {}
        dir_counts = {}
        
        for flow in flows:
            proto = flow['Proto'] 
            if proto in proto_counts:
                proto_counts[proto] += 1
            else:
                proto_counts[proto] = 1
                
            direction = flow['Dir']
            if direction in dir_counts:
                dir_counts[direction] += 1
            else:
                dir_counts[direction] = 1
        
        # Simplified feature set to match the 10 expected features
        # The most important features based on common botnet detection models:
        # 1. Duration
        # 2. Total Packets
        # 3. Total Bytes
        # 4. Source Bytes
        # 5-7. One-hot for protocol (TCP, UDP, other)
        # 8-10. One-hot for direction (uni, bi, other)
        
        # Convert to simplified one-hot for protocol (3 features)
        proto_tcp = 1 if 6 in proto_counts else 0
        proto_udp = 1 if 17 in proto_counts else 0
        proto_other = 1 if any(p not in [6, 17] for p in proto_counts) else 0
        
        # Convert to simplified one-hot for direction (3 features)
        dir_arrow = 1 if 2 in dir_counts else 0  # Unidirectional
        dir_bidir = 1 if 1 in dir_counts else 0  # Bidirectional
        dir_other = 1 if 0 in dir_counts else 0  # Other
        
        # Create 10-feature vector matching the expected model inputs
        features = [
            avg_dur, 
            avg_totpkts, 
            avg_totbytes, 
            avg_srcbytes,
            proto_tcp, 
            proto_udp, 
            proto_other,
            dir_arrow, 
            dir_bidir, 
            dir_other
        ]
        
        X.append(features)
        
        if debug and total_edges <= 3:  # Show details for first 3 valid edges
            print(f"Edge {source_host} -> {dest_host}: {len(flows)} flows")
            print(f"  Features: {features}")

    if verbose:
        print(f"Filtered out {filtered_edges} edges below flow threshold")
        print(f"Extracted features for {total_edges} connections")

    # Create DataFrame with the expected columns
    column_list = [
        'Dur', 'TotPkts', 'TotBytes', 'SrcBytes',
        'Proto_tcp', 'Proto_udp', 'Proto_other',
        'Dir_uni', 'Dir_bi', 'Dir_other'
    ]
    
    X_df = pd.DataFrame(X, columns=column_list) if X else pd.DataFrame(columns=column_list)
    
    if debug:
        print(f"Feature DataFrame shape: {X_df.shape}")
        if not X_df.empty:
            print(f"Feature columns: {X_df.columns.tolist()}")
            print(f"Sample features:\n{X_df.head()}")

    return X_df, edge_info

def predict_traffic(model, X, edge_info, threshold=0.5, verbose=False, debug=False):
    """Make predictions using the joblib model"""
    if X.empty:
        if verbose:
            print("No valid connections to predict")
        return pd.DataFrame()

    if verbose:
        print("Making predictions...")

    # Get model predictions
    try:
        # If the model is a classifier (like RandomForest, DecisionTree, etc.)
        if hasattr(model, 'predict_proba'):
            # Get probabilities
            proba = model.predict_proba(X)
            # Botnet probability is the probability of class 1
            if proba.shape[1] >= 2:  # Ensure we have at least two classes
                if debug:
                    print(f"Classes: {model.classes_}")
                # Find index of class 1 (botnet)
                bot_idx = np.where(model.classes_ == 1)[0]
                if len(bot_idx) > 0:
                    bot_probs = proba[:, bot_idx[0]]
                else:
                    # Default to second class if 1 is not explicitly labeled
                    bot_probs = proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
            else:
                bot_probs = proba[:, 0]
                
            # Apply threshold to probabilities for custom prediction
            custom_preds = (bot_probs >= threshold).astype(int)
            # Class 1 = bot, Class 0 = not bot
            custom_preds = np.where(custom_preds == 1, 1, 2)  # Map to expected output format
                
            # Get direct model predictions as well
            predictions = model.predict(X)
            
            if debug:
                print(f"Prediction classes: {np.unique(predictions)}")
                print(f"Custom prediction classes: {np.unique(custom_preds)}")
                print(f"Sample probabilities: {proba[:5]}")
                print(f"Custom predictions using threshold {threshold}: {custom_preds[:5]}")
                print(f"Model direct predictions: {predictions[:5]}")
        else:
            # For models that only give class output
            predictions = model.predict(X)
            # Fake probabilities (just 0 or 1)
            bot_probs = (predictions == 1).astype(float)
            custom_preds = predictions
    
    except Exception as e:
        print(f"Error during prediction: {e}")
        print("Falling back to direct predictions only")
        predictions = model.predict(X)
        bot_probs = (predictions == 1).astype(float)
        custom_preds = predictions
    
    # Map numeric predictions to labels: 1 = Botnet, 2 = Normal, 0 = Other
    label_map = {
        0: "Other",
        1: "Bot",
        2: "Normal"
    }
    
    # Create a DataFrame with results
    results = pd.DataFrame({
        'Source': [src for src, _ in edge_info],
        'Destination': [dst for _, dst in edge_info],
        'Bot_Probability': bot_probs,
        'Prediction_Class': custom_preds,  # Use custom predictions with threshold
        'Model_Prediction': predictions,  # Original model predictions
        'Classification': [label_map.get(int(p), "Unknown") for p in custom_preds]
    })

    if debug:
        print(f"Results shape: {results.shape}")
        print(f"Sample results:\n{results.head()}")

    return results

def visualize_results(results_df, output_prefix="", verbose=False):
    """Generate visualizations of the detection results"""
    if results_df.empty:
        if verbose:
            print("No results to visualize")
        return

    if verbose:
        print("Generating visualizations...")

    # Create output directory if it doesn't exist
    os.makedirs("visualizations", exist_ok=True)

    # Plot distribution of predictions by class
    plt.figure(figsize=(10, 6))
    results_df['Classification'].value_counts().plot(kind='bar')
    plt.title('Distribution of Traffic Classifications')
    plt.xlabel('Classification')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig(f"visualizations/{output_prefix}classification_distribution.png")

    # Create pie chart of classifications
    plt.figure(figsize=(8, 8))
    results_df['Classification'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.axis('equal')
    plt.title('Traffic Classification Results')
    plt.tight_layout()
    plt.savefig(f"visualizations/{output_prefix}traffic_classification_pie.png")

    # Show top IPs involved in suspicious traffic
    bot_traffic = results_df[results_df['Classification'] == 'Bot']
    if not bot_traffic.empty:
        # Top source IPs
        top_sources = bot_traffic['Source'].value_counts().head(10)
        plt.figure(figsize=(12, 6))
        top_sources.plot(kind='bar')
        plt.title('Top Source IPs in Bot Traffic')
        plt.xlabel('Source IP')
        plt.ylabel('Number of Bot Connections')
        plt.tight_layout()
        plt.savefig(f"visualizations/{output_prefix}top_bot_sources.png")
        
        # Top destination IPs
        top_destinations = bot_traffic['Destination'].value_counts().head(10)
        plt.figure(figsize=(12, 6))
        top_destinations.plot(kind='bar')
        plt.title('Top Destination IPs in Bot Traffic')
        plt.xlabel('Destination IP')
        plt.ylabel('Number of Bot Connections')
        plt.tight_layout()
        plt.savefig(f"visualizations/{output_prefix}top_bot_destinations.png")

    if verbose:
        print(f"Visualizations saved to visualizations/ directory")

def print_summary(results_df):
    """Print a summary of the analysis results with improved formatting"""
    if results_df.empty:
        print("\n" + "=" * 60)
        print("                    ANALYSIS SUMMARY                      ")
        print("=" * 60)
        print("No valid connections were found for analysis")
        return

    total_connections = len(results_df)
    
    # Count by classification
    class_counts = results_df['Classification'].value_counts()
    bot_connections = class_counts.get('Bot', 0)
    normal_connections = class_counts.get('Normal', 0)
    other_connections = class_counts.get('Other', 0)
    
    # Create a colorful banner
    print("\n" + "=" * 60)
    print("               TRAFFIC ANALYSIS SUMMARY                 ")
    print("=" * 60)
    
    # Print general statistics
    summary_table = [
        ["Total Connections Analyzed", f"{total_connections}"],
        ["Bot Traffic Detected", f"{bot_connections} ({bot_connections/total_connections*100:.2f}%)"],
        ["Normal Traffic Detected", f"{normal_connections} ({normal_connections/total_connections*100:.2f}%)"],
        ["Other Traffic Detected", f"{other_connections} ({other_connections/total_connections*100:.2f}%)"]
    ]
    print(tabulate(summary_table, tablefmt="simple"))
    
    # Overall traffic assessment
    print("\n" + "-" * 60)
    if bot_connections > 0:
        bot_percentage = bot_connections/total_connections*100
        if bot_percentage > 50:
            print("HIGH SEVERITY: Majority of traffic appears to be bot activity!")
        elif bot_percentage > 20:
            print("MEDIUM SEVERITY: Significant bot traffic detected")
        elif bot_percentage > 5:
            print("LOW SEVERITY: Some bot traffic detected")
        else:
            print("MINIMAL CONCERN: Small amount of bot traffic detected")
    else:
        print("NO BOTS DETECTED: No suspicious traffic identified")
    
    # If there are bot connections, show the top targets
    if bot_connections > 0:
        print("\n" + "-" * 60)
        print("TOP BOT TRAFFIC PATTERNS:")
        
        # Top source IPs in bot traffic
        bot_traffic = results_df[results_df['Classification'] == 'Bot']
        top_sources = bot_traffic['Source'].value_counts().head(5)
        
        print("\nTop Sources of Bot Traffic:")
        sources_table = []
        for ip, count in top_sources.items():
            sources_table.append([ip, count, f"{count/bot_connections*100:.1f}%"])
        print(tabulate(sources_table, headers=["Source IP", "Count", "% of Bot Traffic"], tablefmt="simple"))
        
        # Top destination IPs in bot traffic
        top_destinations = bot_traffic['Destination'].value_counts().head(5)
        
        print("\nTop Destinations for Bot Traffic:")
        dest_table = []
        for ip, count in top_destinations.items():
            dest_table.append([ip, count, f"{count/bot_connections*100:.1f}%"])
        print(tabulate(dest_table, headers=["Destination IP", "Count", "% of Bot Traffic"], tablefmt="simple"))
    
    print("=" * 60)

def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Print banner
    print("\n" + "=" * 60)
    print("    WIRESHARK TRAFFIC BOT DETECTION ANALYSIS TOOL    ")
    print("=" * 60)
    
    if args.verbose:
        print(f"Loading model from {args.model}...")
    
    # Load the model
    try:
        model = joblib.load(args.model)
        if args.verbose:
            if hasattr(model, 'feature_importances_'):
                print("Model loaded: Model has feature importances")
            else:
                print("Model loaded successfully")
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Please provide a valid joblib model file")
        sys.exit(1)
    
    # Process the CSV file
    data_df = preprocess_wireshark_data(args.csv, verbose=args.verbose, debug=args.debug)
    
    # Build network graph
    graph = build_graph_from_df(data_df, verbose=args.verbose, debug=args.debug, 
                               include_localhost=args.include_localhost)
    
    # Aggregate flows at IP level
    ip_graph = aggregate_flows_by_ip(graph, verbose=args.verbose, debug=args.debug)
    
    # Extract features
    X_df, edge_info = extract_features_from_graph(ip_graph, verbose=args.verbose, 
                                                 debug=args.debug, min_flows=args.min_flows)
    
    if X_df.empty:
        print("\nNo valid connections found for analysis. Please check your data or adjust parameters.")
        sys.exit(0)
    
    # Make predictions
    results = predict_traffic(model, X_df, edge_info, threshold=args.threshold, 
                             verbose=args.verbose, debug=args.debug)
    
    # Save results to CSV
    if not results.empty:
        output_file = args.output
        if args.verbose:
            print(f"Saving results to {output_file}")
        results.to_csv(output_file, index=False)
        
        # Create visualizations if requested
        if args.visualize:
            output_prefix = os.path.splitext(os.path.basename(args.csv))[0] + "_"
            visualize_results(results, output_prefix=output_prefix, verbose=args.verbose)
    
    # Print summary of results
    print_summary(results)
    
    print("\nAnalysis complete.")
    if not results.empty:
        print(f"Results saved to {args.output}")
        if args.visualize:
            print("Visualizations saved to visualizations/ directory")

if __name__ == "__main__":
    main()