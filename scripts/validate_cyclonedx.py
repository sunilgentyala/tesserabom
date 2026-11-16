"""Validate CycloneDX documents against the official 1.6 JSON schema.

Usage: python scripts/validate_cyclonedx.py SCHEMA_DIR doc.json [doc.json ...]
SCHEMA_DIR must hold bom-1.6.schema.json, spdx.schema.json and jsf-0.82.schema.json
from github.com/CycloneDX/specification (schema/).
"""
import json
import os
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource


def main(schema_dir, docs):
    resources = []
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        with open(os.path.join(schema_dir, name), encoding="utf-8") as fh:
            doc = json.load(fh)
        resource = Resource.from_contents(doc)
        resources += [(name, resource), (doc.get("$id", name), resource)]
    with open(os.path.join(schema_dir, "bom-1.6.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = Draft7Validator(schema, registry=Registry().with_resources(resources))
    failed = 0
    for path in docs:
        with open(path, encoding="utf-8") as fh:
            errors = sorted(validator.iter_errors(json.load(fh)), key=lambda e: list(e.path))
        print("%s: %s" % (path, "VALID" if not errors else "%d errors" % len(errors)))
        for err in errors[:10]:
            print("  ", list(err.path)[:5], err.message[:200])
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
