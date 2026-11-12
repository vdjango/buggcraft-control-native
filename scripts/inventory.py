"""AST method/source inventory for this project; tree-sitter is a development dependency."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate():
    from tree_sitter import Language, Parser
    import tree_sitter_cpp

    parser = Parser(Language(tree_sitter_cpp.language()))
    sources, methods = [], []
    for folder in ("include", "src", "tests", "benchmarks", "scripts"):
        for path in sorted((ROOT / folder).rglob("*")):
            if not path.is_file() or path.suffix not in (".hpp", ".cpp", ".py"):
                continue
            raw = path.read_bytes()
            relative = path.relative_to(ROOT).as_posix()
            sources.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
            if path.suffix == ".py":
                tree = ast.parse(raw.decode("utf-8"), filename=relative)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        methods.append({"path": relative, "line": node.lineno, "kind": type(node).__name__,
                                        "name": getattr(node, "name", "<lambda>")})
                continue
            tree = parser.parse(raw)
            if tree.root_node.has_error:
                raise RuntimeError(f"AST parse failed: {relative}")
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type in ("function_definition", "lambda_expression", "class_specifier", "struct_specifier", "function_declarator"):
                    first = raw[node.start_byte:node.end_byte].decode("utf-8").split("\n", 1)[0]
                    methods.append({"path": relative, "line": node.start_point.row + 1,
                                    "kind": node.type, "name": first[:200]})
                stack.extend(reversed(node.children))
    methods.sort(key=lambda row: (row["path"], row["line"], row["kind"]))
    return {"sources.json": sources, "methods.json": methods,
            "dom.json": {"status": "not applicable", "reason": "No HTML/Vue/QML UI in this project"}}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--check", action="store_true")
    args = cli.parse_args()
    output = ROOT / "docs" / "90-代码清单"
    output.mkdir(parents=True, exist_ok=True)
    for name, value in generate().items():
        content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        path = output / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                raise SystemExit(f"Stale inventory: {name}")
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    print("OK AST source/method inventory; DOM not applicable")


if __name__ == "__main__":
    main()
