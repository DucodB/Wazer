import re
from collections import Counter, defaultdict
from pathlib import Path

RESULT_FILENAME_RE = re.compile(
    r"^(?P<location>.+)_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_results\.txt$"
)
COUNT_LINE_RE = re.compile(r"^(?P<name>.+):\s+(?P<count>\d+)\s+\([\d.]+%\)$")


def parse_results_file(file_path: Path) -> dict:
    data = {
        "total_packets": 0,
        "broadcast_frames": 0,
        "main_types": Counter(),
        "subtypes": Counter(),
        "missing_subtypes": set(),
    }

    section = None

    with file_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("Total packets analyzed:"):
                data["total_packets"] = int(line.split(":", 1)[1].strip())
                continue

            if line == "Amount of packets per main frame type:":
                section = "main"
                continue

            if line.startswith("Broadcast frames:"):
                match = re.search(r"Broadcast frames:\s+(\d+)", line)
                if match:
                    data["broadcast_frames"] = int(match.group(1))
                continue

            if line == "Amount of packets per frame subtype:":
                section = "subtypes"
                continue

            if line.startswith("Frame subtypes not observed"):
                section = "missing_subtypes"
                continue

            if line.startswith("Bottom 10%"):
                section = None
                continue

            if section == "missing_subtypes":
                data["missing_subtypes"].add(line)
                continue

            match = COUNT_LINE_RE.match(line)
            if not match:
                continue

            name = match.group("name")
            count = int(match.group("count"))

            if section == "main":
                data["main_types"][name] += count
            elif section == "subtypes":
                data["subtypes"][name] += count

    return data


def combine_by_location(input_dir: Path) -> dict:
    known_subtypes = set()
    combined = defaultdict(
        lambda: {
            "total_packets": 0,
            "broadcast_frames": 0,
            "main_types": Counter(),
            "subtypes": Counter(),
        }
    )

    for result_file in sorted(input_dir.glob("*_results.txt")):
        match = RESULT_FILENAME_RE.match(result_file.name)
        if not match:
            continue

        location = match.group("location")
        parsed = parse_results_file(result_file)

        combined[location]["total_packets"] += parsed["total_packets"]
        combined[location]["broadcast_frames"] += parsed["broadcast_frames"]
        combined[location]["main_types"].update(parsed["main_types"])
        combined[location]["subtypes"].update(parsed["subtypes"])
        known_subtypes.update(parsed["subtypes"].keys())
        known_subtypes.update(parsed["missing_subtypes"])

    for location in combined:
        observed = set(combined[location]["subtypes"].keys())
        combined[location]["never_seen_subtypes"] = sorted(known_subtypes - observed)

    return dict(combined)


def write_summary(location: str, summary: dict, output_dir: Path) -> Path:
    output_path = output_dir / f"{location}_combined_results.txt"
    total_packets = summary["total_packets"]

    with output_path.open("w", encoding="utf-8") as out:
        out.write(f"Location: {location}\n")
        out.write(f"\nTotal packets analyzed: {total_packets}\n\n")

        out.write("Amount of packets per main frame type:\n")
        for frame_type, count in summary["main_types"].most_common():
            percentage = (count / total_packets * 100) if total_packets else 0.0
            out.write(f"{frame_type}: {count} ({percentage:.2f}%)\n")

        broadcast_count = summary["broadcast_frames"]
        broadcast_percentage = (broadcast_count / total_packets * 100) if total_packets else 0.0
        out.write(f"\nBroadcast frames: {broadcast_count} ({broadcast_percentage:.2f}%)\n\n")

        out.write("Amount of packets per frame subtype:\n")
        for subtype, count in summary["subtypes"].most_common():
            percentage = (count / total_packets * 100) if total_packets else 0.0
            out.write(f"{subtype}: {count} ({percentage:.2f}%)\n")

        out.write("\nFrame subtypes not observed in the combined capture set:\n")
        for subtype in summary["never_seen_subtypes"]:
            out.write(f"{subtype}\n")

    return output_path


def main() -> None:
    input_dir = Path("pcap_files")
    output_dir = Path("pcap_files")

    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input directory not found or not a directory: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    combined = combine_by_location(input_dir)
    if not combined:
        raise SystemExit("No matching *_results.txt files found.")

    for location, summary in combined.items():
        output_file = write_summary(location, summary, output_dir)
        print(f"Wrote: {output_file}")


if __name__ == "__main__":
    main()
