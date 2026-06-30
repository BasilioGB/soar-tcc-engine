# basilio-soar

Plataforma SOAR (*Security Orchestration, Automation and Response*) para apoio a resposta a incidentes, com foco em uma engine declarativa de playbooks.

## Escopo

O projeto implementa o núcleo necessário para representar, executar e rastrear playbooks. Ele não pretende possuir a maturidade ou o conjunto completo de recursos de uma plataforma SOAR comercial.

Principais capacidades:

- incidentes, artefatos, tarefas, comunicações e timeline;
- DSL declarativa para playbooks de incidente ou artefato;
- execução automática por eventos e execução manual por analistas;
- filtros, condições, placeholders e encadeamento de resultados;
- decisão condicional com `control.branch`;
- ações internas e conectores HTTP configuráveis;
- execução assíncrona com Celery e Redis;
- API REST, Swagger e interface web;
- logs e resultados persistidos por etapa.

## Arquitetura

O fluxo parte de um incidente, artefato, chamada de API ou ação da interface. A engine seleciona os playbooks aplicáveis, deduplica eventos, cria a execução, processa as etapas e persiste logs, resultados e alterações no caso.

Stack principal: Django, Django REST Framework, Channels, Celery, Redis, PostgreSQL e Docker Compose.

## Execução com Docker

Pré-requisitos:

- Docker;
- Docker Compose.

Prepare o ambiente:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

Aplique as migrações e crie os dados demonstrativos:

```powershell
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_demo --force
```

Serviços disponíveis:

- interface web: `http://localhost:8000/`;
- documentação da API: `http://localhost:8000/api/docs/`;
- schema OpenAPI: `http://localhost:8000/api/schema/`;
- Flower, quando iniciado com o perfil `monitoring`: `http://localhost:5555/`.

Credenciais criadas exclusivamente pela seed demonstrativa:

- `admin / admin123`;
- `soclead / soclead123`;
- `analyst / analyst123`.

Essas credenciais não devem ser utilizadas fora de um ambiente local de demonstração.

## Demonstração com VirusTotal

O fluxo demonstrativo principal utiliza o playbook `Domain auto enrichment`:

1. um incidente recebe um artefato `DOMAIN`;
2. o evento `artifact.created` seleciona o playbook;
3. o valor do artefato é enviado ao conector configurável do VirusTotal;
4. a resposta é normalizada e persistida;
5. `control.branch` seleciona o tratamento adequado;
6. a engine registra tarefa, labels, notas e eventos na timeline.

Para executar uma nova consulta, preencha `VIRUSTOTAL_API_KEY` apenas no `.env` local. Nunca inclua a chave em commits, capturas ou definições de playbook. Os valores retornados pelo serviço são dinâmicos e podem mudar entre execuções.

## Testes

Execução local:

```powershell
.venv\Scripts\python.exe manage.py test --settings=core.test_settings
```

Execução no container:

```powershell
docker compose exec web python manage.py test --settings=core.test_settings
```

A suíte cobre DSL, filtros, resolução de entradas, execução, branching, integrações configuráveis, permissões, API e interface web.

## DSL e modelo de execução

Campos principais: `name`, `type`, `mode`, `triggers`, `filters`, `steps` e `on_error`.

Contexto disponível durante a execução:

- `incident`;
- `artifact` e `artifact_instance`;
- `execution`;
- `actor`;
- `results`;
- `trigger_context`.

Placeholders como `{{artifact.value}}` e `{{results.consultar_vt.stats.malicious}}` permitem que dados do caso e resultados anteriores alimentem novas etapas.

## Limitações atuais

- execução predominantemente sequencial;
- ausência de loops, retries avançados e timeout por etapa;
- ausência de pausa, retomada e aprovação humana intermediária;
- dependência da disponibilidade e do contrato das APIs externas;
- avaliação baseada em testes e cenários controlados, não em operação produtiva.

## Segurança

- `.env`, bancos locais, mídia, caches, artefatos acadêmicos locais e `node_modules` são ignorados pelo Git;
- segredos de integrações não são armazenados na DSL;
- o arquivo `.env.example` contém apenas valores demonstrativos;
- antes de publicar uma versão, execute uma varredura de segredos também no histórico Git.

## Licença

Distribuído sob a licença MIT. Consulte [`LICENSE`](LICENSE).
