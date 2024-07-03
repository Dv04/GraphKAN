import pandas as pd
import numpy as np
import networkx as nx
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GCNConv, global_mean_pool
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


# Load and preprocess data
def load_data(filename="complex_synthetic_data.csv"):
    df = pd.read_csv(filename)
    return df


def create_graph(df):
    G = nx.Graph()
    for idx, row in df.iterrows():
        G.add_node(row["Device_ID"], feature=row["Packet_Size"])
        G.add_edge(row["Source_IP"], row["Destination_IP"])
    return G


def create_pyg_data(G, df):
    node_features = []
    edge_index = []
    labels = []
    node_mapping = {node: i for i, node in enumerate(G.nodes)}

    for node in G.nodes:
        node_features.append([G.nodes[node]["feature"]])
        labels.append(df[df["Device_ID"] == node]["Attack_Type"].iloc[0])

    for edge in G.edges:
        edge_index.append([node_mapping[edge[0]], node_mapping[edge[1]]])
        edge_index.append([node_mapping[edge[1]], node_mapping[edge[0]]])

    x = torch.tensor(node_features, dtype=torch.float)
    edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    y = torch.tensor(
        [1 if label != "Benign" else 0 for label in labels], dtype=torch.long
    )

    data = Data(x=x, edge_index=edge_index, y=y)
    return data


# Define the GraphKAN model
class GraphKAN(nn.Module):
    def __init__(self):
        super(GraphKAN, self).__init__()
        self.conv1 = GCNConv(1, 16)
        self.conv2 = GCNConv(16, 32)
        self.conv3 = GCNConv(32, 64)
        self.fc1 = nn.Linear(64, 32)
        self.fc2 = nn.Linear(32, 2)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.5)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = self.relu(x)
        x = self.conv2(x, edge_index)
        x = self.relu(x)
        x = self.conv3(x, edge_index)
        x = global_mean_pool(x, data.batch)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.dropout(x)
        x = self.fc2(x)
        return x


# Training and evaluation
def train(model, loader, optimizer, criterion):
    model.train()
    total_loss = 0
    for data in loader:
        optimizer.zero_grad()
        output = model(data)
        loss = criterion(output, data.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * data.num_graphs
    return total_loss / len(loader.dataset)


def test(model, loader):
    model.eval()
    correct = 0
    pred_labels = []
    true_labels = []
    with torch.no_grad():
        for data in loader:
            output = model(data)
            pred = output.argmax(dim=1)
            correct += pred.eq(data.y).sum().item()
            pred_labels.extend(pred.cpu().numpy())
            true_labels.extend(data.y.cpu().numpy())
    return correct / len(loader.dataset), classification_report(
        true_labels, pred_labels, target_names=["Benign", "Malicious"]
    )


# Main execution
if __name__ == "__main__":
    df = load_data()
    G = create_graph(df)
    pyg_data = create_pyg_data(G, df)

    # Split data
    train_data, test_data = train_test_split([pyg_data], test_size=0.3, random_state=42)
    train_loader = DataLoader(train_data, batch_size=1, shuffle=True)
    test_loader = DataLoader(test_data, batch_size=1, shuffle=False)

    # Initialize model, optimizer, and loss function
    model = GraphKAN()
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    criterion = nn.CrossEntropyLoss()

    # Train model
    for epoch in range(1, 21):
        loss = train(model, train_loader, optimizer, criterion)
        print(f"Epoch {epoch}, Loss: {loss}")

    # Test model
    accuracy, report = test(model, test_loader)
    print(f"Accuracy: {accuracy}")
    print(report)
