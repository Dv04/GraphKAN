import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils import resample


# Load and preprocess data
def load_data(filename="complex_synthetic_data.csv"):
    df = pd.read_csv(filename)
    return df


def preprocess_data(df):
    categorical_columns = [
        "Device_ID",
        "Protocol",
        "Source_IP",
        "Destination_IP",
        "TCP_Flags",
    ]
    df = pd.get_dummies(df, columns=categorical_columns, drop_first=True)
    attack_type_mapping = {
        "Benign": 0,
        "DDoS": 1,
        "DoS": 2,
        "Recon": 3,
        "Spoofing": 4,
        "MQTT": 5,
    }
    df["Attack_Type"] = df["Attack_Type"].map(attack_type_mapping)
    return df


class KolmogorovArnoldNetwork(nn.Module):
    def __init__(self, input_dim):
        super(KolmogorovArnoldNetwork, self).__init__()
        self.hidden_layers = nn.ModuleList([nn.Linear(1, 32) for _ in range(input_dim)])
        self.output_layer = nn.Linear(
            input_dim * 32, 6
        )  # 6 classes for multiclass classification
        self.activation = nn.ReLU()
        self.dropout = nn.Dropout(0.5)

    def forward(self, x):
        intermediate_outputs = []
        for i in range(x.shape[1]):
            intermediate_output = self.activation(
                self.hidden_layers[i](x[:, i : i + 1])
            )
            intermediate_outputs.append(intermediate_output)
        concatenated_output = torch.cat(intermediate_outputs, dim=1)
        concatenated_output = self.dropout(concatenated_output)
        out = self.output_layer(concatenated_output)
        return out


def train(model, loader, optimizer, criterion):
    model.train()
    total_loss = 0
    for data, target in loader:
        optimizer.zero_grad()
        output = model(data)
        loss = criterion(output, target)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * data.size(0)
    return total_loss / len(loader.dataset)


def test(model, loader):
    model.eval()
    correct = 0
    pred_labels = []
    true_labels = []
    with torch.no_grad():
        for data, target in loader:
            output = model(data)
            pred = output.argmax(dim=1)
            correct += pred.eq(target).sum().item()
            pred_labels.extend(pred.cpu().numpy())
            true_labels.extend(target.cpu().numpy())
    return correct / len(loader.dataset), classification_report(
        true_labels,
        pred_labels,
        target_names=["Benign", "DDoS", "DoS", "Recon", "Spoofing", "MQTT"],
        labels=[0, 1, 2, 3, 4, 5],
    )


def balance_data(X, y):
    data = pd.concat([X, y], axis=1)
    balanced_data = pd.DataFrame()

    for class_value in y.unique():
        class_data = data[data[y.name] == class_value]
        if len(class_data) > 0:
            upsampled_class_data = resample(
                class_data,
                replace=True,  # Sample with replacement
                n_samples=y.value_counts().max(),  # Match number of majority class
                random_state=42,
            )
            balanced_data = pd.concat([balanced_data, upsampled_class_data])

    return balanced_data.iloc[:, :-1], balanced_data.iloc[:, -1]


if __name__ == "__main__":
    df = load_data("complex_synthetic_data.csv")
    df = preprocess_data(df)

    # Ensure all data is numeric
    # df = df.apply(pd.to_numeric, errors="coerce")
    print(df)
    # df = df.dropna()  # Drop rows with any NaN values

    X = df.drop(columns=["Attack_Type"])
    y = df["Attack_Type"]

    train_X, test_X, train_y, test_y = train_test_split(
        X, y, train_size=0.7, test_size=0.3, random_state=42
    )

    train_X, train_y = balance_data(train_X, train_y)

    train_dataset = torch.utils.data.TensorDataset(
        torch.tensor(train_X.values),
        torch.tensor(train_y.values, dtype=torch.long),
    )
    test_dataset = torch.utils.data.TensorDataset(
        torch.tensor(test_X.values, dtype=torch.float32),
        torch.tensor(test_y.values, dtype=torch.long),
    )

    train_loader = torch.utils.data.DataLoader(
        train_dataset, batch_size=32, shuffle=True
    )
    test_loader = torch.utils.data.DataLoader(
        test_dataset, batch_size=32, shuffle=False
    )

    model = KolmogorovArnoldNetwork(input_dim=train_X.shape[1])
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    class_counts = train_y.value_counts()
    class_weights = torch.tensor(
        [1.0 / class_counts[i] for i in range(6)], dtype=torch.float
    )
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    for epoch in range(1, 21):
        loss = train(model, train_loader, optimizer, criterion)
        print(f"Epoch {epoch}, Loss: {loss}")

    accuracy, report = test(model, test_loader)
    print(f"Accuracy: {accuracy}")
    print(report)
