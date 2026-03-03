This folder contains PlantUML sources for CodeGuardian architecture diagrams.

Files:
- `sequence_upload_scan.puml` — Sequence diagram for upload → scan → reasoner → persist.
- `class_core.puml` — Class diagram for core classes (`LLMClient`, `NIMClient`, `SageMakerClient`, `Engine`, `Reasoner`, `Persistence`).
- `deployment.puml` — Deployment diagram showing Browser, Server, Inference (NIM/SageMaker), and KB/FAISS.

Render instructions (CLI):

````markdown
This folder contains PlantUML sources for CodeGuardian architecture diagrams.

Diagrams included (standard UML set):
- `er_data_model.puml` — Entity-Relationship diagram for reports, findings, and sessions.
- `class_core.puml` — Class diagram for core components (`App`, `Engine`, `LLMClient`/`NIMClient`, `Persistence`).
- `use_case.puml` — Use Case diagram showing actors and main flows (Upload, View Reports, Trigger Scan).
- `activity_scan.puml` — Activity diagram for the upload → analysis → persist workflow.
- `sequence_upload_scan.puml` — Sequence diagram for an upload and scan interaction.

Note: SageMaker references have been removed; diagrams reflect the primary LLM integration via NVIDIA NIM (no AWS SageMaker dependency).

Render instructions (CLI):

```bash
# render PNG
plantuml -tpng er_data_model.puml
plantuml -tpng class_core.puml
plantuml -tpng use_case.puml
plantuml -tpng activity_scan.puml
plantuml -tpng sequence_upload_scan.puml

# render SVG
plantuml -tsvg er_data_model.puml
plantuml -tsvg class_core.puml
plantuml -tsvg use_case.puml
plantuml -tsvg activity_scan.puml
plantuml -tsvg sequence_upload_scan.puml
```

Or open the files in VS Code with the PlantUML extension and export via context menu.

````
