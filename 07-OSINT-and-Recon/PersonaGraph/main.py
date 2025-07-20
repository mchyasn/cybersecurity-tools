import argparse
from modules.collector import collect_entities
from modules.graph_builder import build_graph

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PersonaGraph - Human-Centric OSINT Mapper")
    parser.add_argument("-i", "--input", required=True, help="Username, email, or phone number")
    parser.add_argument("-o", "--output", default="output/graph.html", help="Path to save the graph")
    parser.add_argument("--config", default="configs/config.yaml", help="Path to config YAML")
    args = parser.parse_args()

    entities = collect_entities(args.input, args.config)
    build_graph(entities, args.output)
