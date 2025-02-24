import csv
import io
from typing import Dict, Any


def flatten_json(json_obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """
    Flatten a nested JSON object into a single level dictionary.
    Skip parent objects and keep only leaf values.
    """
    flattened = {}

    for key, value in json_obj.items():
        # If value is a nested dictionary, flatten it recursively
        if isinstance(value, dict):
            flattened.update(flatten_json(value, f"{prefix}{key}_"))
        else:
            # Only add leaf nodes to the flattened dictionary
            flattened[f"{prefix}{key}"] = value

    return flattened


def convert_json_to_csv(json_data: Dict[str, Any]) -> bytes:
    """
    Convert JSON data to CSV format.
    Returns CSV content as bytes.
    """
    # Extract and flatten the inference_result
    if "inference_result" in json_data:
        flattened_data = flatten_json(json_data["inference_result"])
    else:
        flattened_data = flatten_json(json_data)

    # Create a CSV in memory
    csv_buffer = io.StringIO()
    fieldnames = list(flattened_data.keys())
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow(flattened_data)

    # Return CSV as bytes
    return csv_buffer.getvalue().encode("utf-8")


# # Example usage:
# if __name__ == "__main__":
#     # Sample data (you would load this from a file in practice)
#     input_data = {
#         "inference_result": {
#             # Your JSON data here
#         }
#     }

#     # Convert to CSV
#     json_to_csv(input_data, "output.csv")
