from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List

from integrations import registry
from integrations.models import IntegrationDefinition

# Public content -----------------------------------------------------------------

GUIDE_STEPS: List[dict] = [
    {
        "title": "1. Defina os metadados basicos",
        "body": (
            "Preencha `name`, `category`, `description`, `type` e `mode`. O tipo define o contexto "
            "(`incident` ou `artifact`) e o modo determina se o gatilho e automatico ou manual."
        ),
        "items": [
            "Use nomes objetivos (ex.: \"Phishing triage\").",
            "Agrupe playbooks do mesmo contexto usando a mesma categoria (ex.: \"Phishing\").",
            "Habilite o playbook apenas quando estiver pronto para uso (`enabled`).",
            "Descreva o objetivo e os pre requisitos para que o time entenda rapidamente o fluxo.",
        ],
    },
    {
        "title": "2. Configure disparos ou filtros",
        "body": (
            "Playbooks automaticos exigem `triggers` com eventos como `incident.created` ou "
            "`artifact.created`. Playbooks manuais ignoram triggers e utilizam `filters` para "
            "controlar quando aparecem na interface."
        ),
        "items": [
            "Eventos suportados: incident.created, incident.updated, artifact.created.",
            "Filtros de trigger aceitam chaves como labels, status, severity, type ou changed_fields.",
            "Filtros manuais usam `target` (`incident` ou `artifact`) e `conditions` para labels, tipos e valores.",
        ],
    },
    {
        "title": "3. Modele os steps",
        "body": (
            "Cada item em `steps` deve ter `name`, `action` e `input`. Combine atualizacoes de incidente, "
            "criacao de tarefas, comunicacoes e conectores HTTP."
        ),
        "items": [
            "Prefira nomes em snake_case para facilitar a leitura nos logs.",
            "Documente apenas os campos necessarios dentro de `input`.",
            "A execucao atual e linear, mas cada step pode usar `when` para condicionais simples.",
            "Garanta que todas as acoes externas possuam as credenciais e secrets configurados.",
        ],
    },
    {
        "title": "4. Defina comportamento em caso de erro",
        "body": (
            "Use `on_error: \"continue\"` para seguir com o fluxo mesmo que um passo falhe ou `stop` para interromper "
            "a execucao imediatamente."
        ),
        "items": [
            "Logue mensagens claras nos steps para facilitar troubleshooting.",
            "Considere adicionar notas ou labels no incidente quando ocorrer um erro critico.",
            "Placeholders simples em `input` sao resolvidos no runtime, por exemplo `{{incident.id}}`, `{{artifact.value}}` e `{{results.step_name.field}}`.",
            "Filtros simples em pipeline tambem sao suportados, como `{{incident.assignee.username|default:\"unassigned\"|upper}}`.",
            "Use `when` com operadores como `equals`, `in`, `contains`, `all`, `any` e `not` para controlar a execucao de um step.",
        ],
    },
    {
        "title": "5. Valide e publique",
        "body": (
            "Utilize a pagina de criacao/edicao ou o endpoint `/api/v1/playbooks/validate/` para validar a DSL. "
            "Execute em um incidente de laboratorio e revise a timeline e os logs de execucao."
        ),
        "items": [
            "Versione a DSL junto com o repositorio da equipe.",
            "Planeje testes periodicos para garantir que os conectores HTTP continuam respondendo.",
            "Conectores HTTP devolvem o corpo da resposta em `results.nome_do_step`; o playbook trata esse JSON nos steps seguintes.",
        ],
    },
]

DSL_SCAFFOLD = """{
  "name": "Phishing triage",
  "description": "Fluxo de resposta padrao para phishing reportado.",
  "type": "incident",
  "mode": "automatic",
  "enabled": true,
  "triggers": [
    {
      "event": "incident.created",
      "filters": {"labels": ["phishing"]}
    }
  ],
  "steps": [
    {
      "name": "registrar_contexto",
      "action": "incident.add_note",
      "input": {"message": "Playbook iniciado automaticamente"}
    }
  ],
  "on_error": "continue"
}"""

REFERENCE_SNIPPETS: List[dict] = [
    {
        "title": "Playbook manual para incidentes",
        "snippet": """{
  "name": "Phishing checklist",
  "type": "incident",
  "mode": "manual",
  "filters": [
    {"target": "incident", "conditions": {"labels": ["phishing"], "severity": ["MEDIUM", "HIGH"]}}
  ],
  "steps": [
    {"name": "abrir_tarefa", "action": "task.create", "input": {"title": "Validar anexos", "owner": "analyst"}},
    {"name": "registrar_nota", "action": "incident.add_note", "input": {"message": "Checklist manual executado"}}
  ],
  "on_error": "continue"
}""",
    },
    {
        "title": "Playbook manual para artefatos",
        "snippet": """{
  "name": "IOC enrichment manual",
  "type": "artifact",
  "mode": "manual",
  "filters": [
    {"target": "artifact", "conditions": {"type": ["DOMAIN"]}}
  ],
  "steps": [
    {"name": "consultar_virustotal", "action": "virustotal_config.domain_lookup", "input": {"domain": "{{artifact.value}}"}},
    {"name": "persistir_vt", "action": "artifact.update_attributes", "input": {"attributes": {"virustotal": "{{results.consultar_virustotal}}"}}},
    {"name": "anotar_resultado", "action": "incident.add_note", "input": {"message": "Dominio enriquecido manualmente via conector HTTP"}}
  ],
  "on_error": "continue"
}""",
    },
    {
        "title": "Consulta de hash de arquivo no VirusTotal",
        "snippet": """{
  "name": "File hash lookup",
  "type": "artifact",
  "mode": "manual",
  "filters": [
    {"target": "artifact", "conditions": {"type": ["FILE"]}}
  ],
  "steps": [
    {"name": "consultar_vt", "action": "virustotal_config.file_hash_report", "input": {"hash": "{{artifact_instance.sha256}}"}},
    {"name": "persistir_vt", "action": "artifact.update_attributes", "input": {"attributes": {"virustotal": "{{results.consultar_vt}}"}}},
    {"name": "registrar_nota", "action": "incident.add_note", "input": {"message": "Hash do arquivo consultado via conector HTTP do VirusTotal."}}
  ],
  "on_error": "continue"
}""",
    },
]

TRIGGER_EXAMPLE_METADATA: List[dict[str, Any]] = [
    {
        "title": "Incidente criado com labels e severidade",
        "summary": "Dispara no evento de criacao quando o incidente atende labels/status/severidade.",
        "event": "incident.created",
        "supported_types": ["incident"],
        "supported_filters": ["labels", "any_label", "status", "severity", "assignee"],
        "example_filters": {
            "incident": {
                "labels": ["phishing"],
                "status": ["NEW", "IN_PROGRESS"],
                "severity": ["HIGH", "CRITICAL"],
            }
        },
    },
    {
        "title": "Incidente atualizado por campos sensiveis",
        "summary": "Aciona apenas quando campos monitorados forem alterados no update.",
        "event": "incident.updated",
        "supported_types": ["incident"],
        "supported_filters": ["labels", "any_label", "status", "severity", "assignee", "changed_fields"],
        "example_filters": {
            "incident": {
                "changed_fields": ["severity", "status", "labels"],
                "severity": ["MEDIUM", "HIGH", "CRITICAL"],
            }
        },
    },
    {
        "title": "Artefato criado com tipo e valor suspeito",
        "summary": "Filtra por tipo do artefato, conteudo do valor e labels do incidente.",
        "event": "artifact.created",
        "supported_types": ["artifact"],
        "supported_filters": ["type", "value_contains", "incident_labels", "attribute_equals"],
        "example_filters": {
            "artifact": {
                "type": ["DOMAIN", "URL"],
                "value_contains": ["login", "secure"],
                "incident_labels": ["phishing"],
            }
        },
    },
    {
        "title": "Artefato criado com validacao de atributo",
        "summary": "Exemplo avancado usando attribute_equals e placeholder dinamico.",
        "event": "artifact.created",
        "supported_types": ["artifact"],
        "supported_filters": ["type", "value_contains", "incident_labels", "attribute_equals"],
        "example_filters": {
            "artifact": {
                "type": ["IP"],
                "attribute_equals": {"expected_type": "{{artifact.type}}"},
            }
        },
    },
]

ACTION_METADATA: Dict[str, Dict[str, object]] = {
    "incident.add_note": {
        "category": "Incidente",
        "summary": "Registra nota ou evento na timeline do incidente.",
        "inputs": {
            "message": "Texto obrigatorio da nota.",
            "entry_type": "Opcional. Tipo da entrada (padrao NOTE).",
            "meta": "Campos extras armazenados junto a nota.",
        },
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"message": "Playbook executado para o incidente {{incident.id}}"},
            "artifact": {"message": "Artefato {{artifact.value}} analisado no incidente {{incident.id}}"},
        },
    },
    "incident.add_label": {
        "category": "Incidente",
        "summary": "Adiciona uma unica label ao incidente.",
        "inputs": {"label": "Nome da label obrigatoria."},
        "notes": "Tambem disponivel `incident.add_labels` para uma lista.",
        "supported_types": ["incident", "artifact"],
        "example_input": {"incident": {"label": "triaged"}, "artifact": {"label": "artifact-reviewed"}},
    },
    "incident.add_labels": {
        "category": "Incidente",
        "summary": "Adiciona varias labels ao incidente.",
        "inputs": {"labels": "Lista de labels a adicionar."},
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"labels": ["auto-playbook", "needs-review"]},
            "artifact": {"labels": ["ioc-reviewed", "needs-review"]},
        },
    },
    "incident.update_status": {
        "category": "Incidente",
        "summary": "Atualiza o status do incidente.",
        "inputs": {"status": "Novo status", "reason": "Motivo opcional gravado na timeline."},
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"status": "IN_PROGRESS", "reason": "Playbook iniciou atendimento"},
            "artifact": {"status": "IN_PROGRESS", "reason": "Analise do artefato em andamento"},
        },
    },
    "incident.assign": {
        "category": "Incidente",
        "summary": "Atribui o incidente para um usuario.",
        "inputs": {"assignee": "Username ou id do usuario.", "assignee_id": "Alias para `assignee`."},
        "supported_types": ["incident", "artifact"],
        "example_input": {"incident": {"assignee": "soclead"}, "artifact": {"assignee": "analyst"}},
    },
    "incident.update_impact": {
        "category": "Incidente",
        "summary": "Atualiza metadados de impacto e classificacao.",
        "inputs": {
            "impact_systems": "Lista de sistemas afetados.",
            "risk_score": "Pontuacao numerica de risco.",
            "severity": "Nova severidade sugerida.",
            "estimated_cost": "Custo estimado (decimal).",
            "business_unit": "Unidade de negocio envolvida.",
            "data_classification": "Classificacao de dados.",
        },
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"severity": "HIGH", "risk_score": 80, "business_unit": "Financeiro"},
            "artifact": {"severity": "MEDIUM", "risk_score": 55, "business_unit": "SOC"},
        },
    },
    "incident.custom_fields.set": {
        "category": "Incidente",
        "summary": "Define um campo customizado do incidente por api_name ou internal_id.",
        "inputs": {
            "api_name": "Nome de API do campo (recomendado).",
            "internal_id": "ID interno do campo (alternativa ao api_name).",
            "value": "Valor do campo customizado.",
        },
        "notes": "Uso recomendado com api_name (ex.: `vendas_afetadas`).",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"api_name": "vendas_afetadas", "value": 3},
            "artifact": {"api_name": "ioc_contexto", "value": {"type": "{{artifact.type}}", "value": "{{artifact.value}}"}},
        },
    },
    "incident.custom_fields.merge": {
        "category": "Incidente",
        "summary": "Atualiza varios campos customizados em lote.",
        "inputs": {
            "fields": "Objeto JSON com pares api_name->valor ou internal_id->valor.",
        },
        "notes": "As chaves de `fields` podem ser api_name (preferivel) ou internal_id.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"fields": {"vendas_afetadas": 3, "canal_primario": "email"}},
            "artifact": {"fields": {"ultimo_ioc": "{{artifact.value}}"}},
        },
    },
    "incident.escalate": {
        "category": "Incidente",
        "summary": "Define nivel de escalacao e alvos de notificacao.",
        "inputs": {"level": "Nivel de escalacao (texto livre).", "targets": "Lista de destinatarios."},
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"level": "tier2", "targets": ["SOC Lead", "Infra"]},
            "artifact": {"level": "tier2", "targets": ["Threat Intel"]},
        },
    },
    "incident.log_action": {
        "category": "Incidente",
        "summary": "Cria entrada no audit log com verbo customizado.",
        "inputs": {"verb": "Identificador obrigatorio.", "meta": "Dicionario opcional com detalhes."},
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"verb": "playbook.started", "meta": {"source": "playbook"}},
            "artifact": {"verb": "artifact.reviewed", "meta": {"artifact": "{{artifact.value}}"}},
        },
    },
    "task.create": {
        "category": "Tarefas",
        "summary": "Cria follow up vinculado ao incidente.",
        "inputs": {
            "title": "Titulo da tarefa (obrigatorio).",
            "owner": "Username ou id do responsavel (opcional).",
            "eta": "Data limite ISO 8601.",
        },
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"title": "Validar evidencias do incidente", "owner": "analyst"},
            "artifact": {"title": "Analisar IOC {{artifact.value}}", "owner": "analyst"},
        },
    },
    "task.complete": {
        "category": "Tarefas",
        "summary": "Marca tarefa como concluida ou nao.",
        "inputs": {
            "task_id": "Identificador da tarefa (obrigatorio se `title` ausente).",
            "title": "Titulo para busca alternativa.",
            "done": "Booleano (padrao True).",
        },
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"title": "Validar evidencias do incidente", "done": True},
            "artifact": {"title": "Analisar IOC {{artifact.value}}", "done": True},
        },
    },
    "communication.log": {
        "category": "Comunicacao",
        "summary": "Registra uma comunicacao interna no incidente.",
        "inputs": {
            "channel": "Canal (padrao internal).",
            "recipient_team": "Equipe destino.",
            "recipient_user": "Username ou id do usuario destino.",
            "message": "Mensagem obrigatoria.",
        },
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"channel": "internal", "recipient_team": "SOC", "message": "Incidente priorizado para atendimento."},
            "artifact": {"channel": "internal", "recipient_team": "Threat Intel", "message": "IOC {{artifact.value}} enviado para revisao."},
        },
    },
    "artifact.create": {
        "category": "Artefatos",
        "summary": "Cria novo artefato associado ao incidente.",
        "inputs": {"value": "Valor do artefato (obrigatorio).", "type": "Tipo (padrao OTHER)."},
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"value": "suspicious.example", "type": "DOMAIN"},
            "artifact": {"value": "{{artifact.value}}", "type": "DOMAIN"},
        },
    },
    "artifact.create_email_from_raw": {
        "category": "Artefatos",
        "summary": "Cria um artefato EMAIL proprio a partir de uma mensagem .eml/raw.",
        "inputs": {
            "raw_message": "Mensagem bruta obrigatoria em formato .eml/raw.",
            "value": "Valor opcional para o artefato. Se ausente, usa message-id ou subject.",
        },
        "notes": "Persiste a mensagem bruta em `attributes.email_raw` e os cabecalhos basicos em `attributes.email_headers`.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"raw_message": "{{results.coletar_email.raw_message}}"},
            "artifact": {"raw_message": "{{artifact.attributes.email_raw}}"},
        },
    },
    "artifact.parse_email_headers": {
        "category": "Artefatos",
        "summary": "Extrai remetente, reply-to, subject, message-id, received e SPF/DKIM/DMARC.",
        "inputs": {
            "artifact_id": "ID opcional do artefato EMAIL. Se ausente, usa o artefato atual.",
            "raw_message": "Mensagem bruta opcional para parse sem depender de artefato.",
        },
        "notes": "Se houver artefato resolvido, persiste o resultado em `attributes.email_headers`.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"artifact_id": "{{results.criar_email.artifact_id}}"},
            "artifact": {},
        },
    },
    "artifact.extract_links": {
        "category": "Artefatos",
        "summary": "Extrai URLs encontradas nos corpos text/plain e text/html do e-mail.",
        "inputs": {
            "artifact_id": "ID opcional do artefato EMAIL. Se ausente, usa o artefato atual.",
            "raw_message": "Mensagem bruta opcional para extracao sem depender de artefato.",
        },
        "notes": "Se houver artefato resolvido, persiste o resultado em `attributes.email_links`.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"artifact_id": "{{results.criar_email.artifact_id}}"},
            "artifact": {},
        },
    },
    "artifact.extract_attachments_metadata": {
        "category": "Artefatos",
        "summary": "Extrai metadados de anexos MIME, incluindo filename, tamanho, tipo e SHA256.",
        "inputs": {
            "artifact_id": "ID opcional do artefato EMAIL. Se ausente, usa o artefato atual.",
            "raw_message": "Mensagem bruta opcional para extracao sem depender de artefato.",
        },
        "notes": "Se houver artefato resolvido, persiste o resultado em `attributes.email_attachments`.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"artifact_id": "{{results.criar_email.artifact_id}}"},
            "artifact": {},
        },
    },
    "artifact.extract_iocs_from_email": {
        "category": "Artefatos",
        "summary": "Extrai URLs, dominios, IPs e nomes de arquivo de uma mensagem de e-mail.",
        "inputs": {
            "artifact_id": "ID opcional do artefato EMAIL. Se ausente, usa o artefato atual.",
            "raw_message": "Mensagem bruta opcional para extracao sem depender de artefato.",
        },
        "notes": "Se houver artefato resolvido, persiste o resultado em `attributes.email_iocs`.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"artifact_id": "{{results.criar_email.artifact_id}}"},
            "artifact": {},
        },
    },
    "artifact.update_attributes": {
        "category": "Artefatos",
        "summary": "Atualiza os atributos JSON de um artefato existente.",
        "inputs": {
            "artifact_id": "ID explicito do artefato. Se ausente, usa o artefato atual do contexto.",
            "attributes": "Objeto JSON obrigatorio com os atributos a persistir.",
            "merge": "Booleano opcional. Se true, faz merge; se false, substitui o objeto inteiro.",
        },
        "notes": "Falha se nao houver `artifact_instance` no contexto e `artifact_id` nao for informado.",
        "supported_types": ["artifact"],
        "example_input": {
            "artifact": {"attributes": {"source": "playbook", "last_verdict": "{{results.step_anterior.verdict}}"}},
        },
    },
    "artifact.update": {
        "category": "Artefatos",
        "summary": "Atualiza valor e/ou tipo de um artefato existente.",
        "inputs": {
            "artifact_id": "ID explicito do artefato. Se ausente, usa o artefato atual do contexto.",
            "value": "Novo valor do artefato.",
            "type": "Novo tipo do artefato.",
        },
        "notes": "Falha se nenhum campo mutavel for informado ou se nao houver artefato resolvido.",
        "supported_types": ["artifact"],
        "example_input": {
            "artifact": {"value": "{{artifact.value}}", "type": "{{artifact.type}}"},
        },
    },
    "artifact.update_hash": {
        "category": "Artefatos",
        "summary": "Atualiza explicitamente o hash SHA256 de um artefato.",
        "inputs": {
            "artifact_id": "ID explicito do artefato. Se ausente, usa o artefato atual do contexto.",
            "sha256": "Hash SHA256 obrigatorio.",
        },
        "notes": "Util para fluxos que enriquecem ou enviam arquivos e precisam persistir o hash no artefato atual.",
        "supported_types": ["artifact"],
        "example_input": {
            "artifact": {"sha256": "{{results.step_anterior.sha256}}"},
        },
    },
    "artifact.extract_domain_from_email": {
        "category": "Artefatos",
        "summary": "Extrai dominio de um email e cria artefato DOMAIN.",
        "inputs": {
            "email": "Endereco para extracao (opcional se `artifact_id`).",
            "artifact_id": "ID de um artefato de email existente.",
        },
        "notes": "Adiciona label `domain-extracted` ao incidente.",
        "supported_types": ["incident", "artifact"],
        "example_input": {
            "incident": {"email": "suspicious@exemplo.com"},
            "artifact": {"email": "{{artifact.value}}"},
        },
    },
}


# Helpers consumed by the UI ------------------------------------------------------


def _normalized_supported_types(metadata: dict[str, Any]) -> list[str]:
    supported_types = metadata.get("supported_types") or ["incident", "artifact"]
    return [str(item) for item in supported_types]


def _build_step_example(
    *,
    name: str,
    inputs: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "name": name,
            "action": name if "." in name else name,
            "input": inputs,
        },
        indent=2,
        ensure_ascii=False,
    )


def _native_example_steps(action_name: str, metadata: dict[str, Any]) -> dict[str, str]:
    supported_types = _normalized_supported_types(metadata)
    example_inputs = metadata.get("example_input") or {}
    examples: dict[str, str] = {}
    for playbook_type in supported_types:
        inputs = example_inputs.get(playbook_type) or example_inputs.get("incident") or {}
        examples[playbook_type] = json.dumps(
            {
                "name": action_name.replace(".", "_"),
                "action": action_name,
                "input": inputs,
            },
            indent=2,
            ensure_ascii=False,
        )
    return examples


def _connector_param_example(param_name: str, playbook_type: str) -> Any:
    normalized = param_name.lower()
    if playbook_type == "artifact":
        if normalized in {"domain", "ip", "url", "value"}:
            return "{{artifact.value}}"
        if normalized in {"hash", "sha256"}:
            return "{{artifact_instance.sha256}}"
        if normalized.endswith("_id"):
            return "{{results.step_anterior.%s}}" % normalized
        return "{{results.step_anterior.%s}}" % normalized
    if normalized in {"incident_id", "id"}:
        return "{{incident.id}}"
    if normalized == "severity":
        return "{{incident.severity}}"
    if normalized.endswith("_id"):
        return "{{results.step_anterior.%s}}" % normalized
    return "TODO_%s" % normalized.upper()


def _connector_example_steps(connector: IntegrationDefinition) -> dict[str, str]:
    examples: dict[str, str] = {}
    for playbook_type in ("incident", "artifact"):
        example_input = {
            param: _connector_param_example(param, playbook_type)
            for param in connector.expected_params
        }
        examples[playbook_type] = json.dumps(
            {
                "name": connector.action_name.replace(".", "_"),
                "action": connector.action_name,
                "input": example_input,
            },
            indent=2,
            ensure_ascii=False,
        )
    return examples


def _connector_output_descriptions(connector: IntegrationDefinition) -> dict[str, str]:
    if not connector.output_template:
        return {}
    return {
        key: f"Disponivel em `results.nome_do_step.{key}`."
        for key in connector.output_template.keys()
    }


def get_action_catalog() -> List[dict]:
    """Return actions grouped by category with metadata."""
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for action_name in registry.list_actions():
        metadata = ACTION_METADATA.get(
            action_name,
            {
                "category": "Outros",
                "summary": "Descricao em desenvolvimento.",
                "inputs": {},
                "notes": "",
            },
        )
        grouped[metadata["category"]].append(
            {
                "name": action_name,
                "title": action_name,
                "action_kind": "Nativa",
                "summary": metadata.get("summary", ""),
                "inputs": metadata.get("inputs", {}),
                "outputs": {},
                "notes": metadata.get("notes", ""),
                "supported_types": _normalized_supported_types(metadata),
                "example_steps": _native_example_steps(action_name, metadata),
            }
        )

    configured_connectors = (
        IntegrationDefinition.objects.filter(enabled=True)
        .order_by("action_name")
    )
    configured_entries: list[dict] = []
    for connector in configured_connectors:
        expected_params = {
            param: "Parametro esperado pelo conector HTTP."
            for param in connector.expected_params
        }
        notes_parts = [f"Revision {connector.revision}.", f"Metodo {connector.method}."]
        notes_parts.append(
            f"Usa o secret '{connector.secret_ref.name}' com estrategia '{connector.auth_strategy}'."
        )
        if connector.timeout_seconds:
            notes_parts.append(f"Timeout padrao de {connector.timeout_seconds}s.")
        if connector.output_template:
            notes_parts.append(
                "O conector expoe um output filtrado em `results.nome_do_step` para os proximos steps."
            )
        else:
            notes_parts.append(
                "O corpo da resposta fica disponivel em `results.nome_do_step` para os proximos steps."
            )
        configured_entries.append(
            {
                "name": connector.action_name,
                "title": connector.name,
                "action_kind": "Configurada",
                "summary": connector.description or "Conector HTTP configurado dinamicamente.",
                "inputs": expected_params,
                "outputs": _connector_output_descriptions(connector),
                "notes": " ".join(notes_parts),
                "supported_types": ["incident", "artifact"],
                "example_steps": _connector_example_steps(connector),
            }
        )
    if configured_entries:
        grouped["Conectores HTTP"].extend(configured_entries)

    catalog = []
    for category in sorted(grouped):
        catalog.append(
            {
                "category": category,
                "actions": sorted(grouped[category], key=lambda item: item["name"]),
            }
        )
    return catalog


def get_trigger_examples() -> List[dict]:
    examples: list[dict] = []
    for item in TRIGGER_EXAMPLE_METADATA:
        supported_types = [str(value) for value in (item.get("supported_types") or ["incident"])]
        per_type_filters = item.get("example_filters") or {}
        snippets: dict[str, str] = {}
        for playbook_type in supported_types:
            filters = (
                per_type_filters.get(playbook_type)
                or per_type_filters.get("incident")
                or per_type_filters.get("artifact")
                or {}
            )
            snippets[playbook_type] = json.dumps(
                {"event": item["event"], "filters": filters},
                indent=2,
                ensure_ascii=False,
            )
        examples.append(
            {
                "title": item["title"],
                "summary": item.get("summary", ""),
                "event": item["event"],
                "supported_types": supported_types,
                "supported_filters": item.get("supported_filters") or [],
                "example_triggers": snippets,
            }
        )
    return examples


def get_guide_steps() -> List[dict]:
    return GUIDE_STEPS


def get_reference_snippets() -> List[dict]:
    return REFERENCE_SNIPPETS
