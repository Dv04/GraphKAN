import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Assuming df_0218, df_0405, and df_1516 are already defined
df_list = [df_0218, df_0405, df_1516]
df_names = ["df_0218", "df_0405", "df_1516"]


def plot_count_vs_duration(df_list, df_names):
    plt.figure(figsize=(17, 6))

    # Plot histogram of each dataset
    for i, df in enumerate(df_list):
        # Create a subplot
        plt.subplot(1, len(df_list), i + 1)
        df["total_counts"] = pd.to_numeric(df["total.counts"], errors="coerce")
        sns.scatterplot(
            x="duration.s",
            y="total_counts",
            size="radial",
            hue="energy.kev",
            data=df,
            alpha=0.7,
        )

        plt.title(f"Count vs Duration for {df_names[i]}")
        plt.xlabel("Flare Duration (s)")
        plt.ylabel("Total Counts (s)")
        plt.legend(title="Energy Band (keV)", loc="upper right")

    # Adjust layout
    plt.tight_layout()

    # Show the plot
    plt.show()


plot_count_vs_duration(df_list, df_names)
