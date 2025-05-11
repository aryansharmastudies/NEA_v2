import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Define the components of the system
components = {
    "Client": ["User Input", "Client DB", "File Events", "Sync Queue"],
    "Network": ["TCP Socket (8000, 9000)"],
    "Server": ["Server DB", "Sync Worker", "Message Handler", "Folder/Device/User Management"],
}

# Define the flows between components
flows = [
    ("User Input", "Client DB"),
    ("User Input", "TCP Socket (8000, 9000)"),
    ("Client DB", "TCP Socket (8000, 9000)"),
    ("File Events", "Sync Queue"),
    ("Sync Queue", "TCP Socket (8000, 9000)"),
    ("TCP Socket (8000, 9000)", "Server DB"),
    ("TCP Socket (8000, 9000)", "Message Handler"),
    ("Message Handler", "Folder/Device/User Management"),
    ("Message Handler", "Sync Worker"),
    ("Sync Worker", "Server DB"),
]

# Coordinates for the components in the diagram
positions = {
    "User Input": (1, 3),
    "Client DB": (1, 2),
    "File Events": (1, 1),
    "Sync Queue": (1, 0),

    "TCP Socket (8000, 9000)": (4, 1.5),

    "Server DB": (7, 3),
    "Message Handler": (7, 2),
    "Sync Worker": (7, 1),
    "Folder/Device/User Management": (7, 0),
}

# Create the diagram
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 9)
ax.set_ylim(-1, 4)
ax.axis('off')

# Draw nodes
for comp, (x, y) in positions.items():
    ax.add_patch(mpatches.FancyBboxPatch((x-0.4, y-0.2), 1.5, 0.5, boxstyle="round,pad=0.1", fc="lightblue", ec="black"))
    ax.text(x+0.35, y, comp, ha='center', va='center', fontsize=9)

# Draw arrows for data flow
for start, end in flows:
    x1, y1 = positions[start]
    x2, y2 = positions[end]
    ax.annotate("",
                xy=(x2, y2), xycoords='data',
                xytext=(x1, y1), textcoords='data',
                arrowprops=dict(arrowstyle="->", lw=1.5, color='gray'))

plt.title("Level 0 Data Flow Diagram", fontsize=14)
plt.tight_layout()
plt.show()
