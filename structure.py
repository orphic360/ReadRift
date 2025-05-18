import os

# Define the directory structure
structure = {
    "app": [
        "static/css/",
        "templates/",
        "__init__.py",
        "models.py",
        "routes.py",
        "forms.py"
    ],
    ".": [
        "config.py",
        "run.py"
    ]
}

# Function to create the directories and files
def create_structure(structure):
    for base_dir, paths in structure.items():
        for path in paths:
            full_path = os.path.join(base_dir, path)
            if full_path.endswith('/'):
                # Create directories
                os.makedirs(full_path, exist_ok=True)
            else:
                # Create files
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'w') as f:
                    f.write("")  # Create an empty file

# Create the structure
create_structure(structure)

print("Project structure created successfully!")
