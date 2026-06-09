#!/usr/bin/env python3
"""Add missing data-directory explanations to explanations_pt.json (pt-BR)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "config"
PT_PATH = ROOT / "explanations_pt.json"

TRANSLATIONS = {
    "Export Directory": {
        "title": "Diretório de Exportação",
        "description": "Contém informações sobre funções e dados que o módulo exporta para uso por outros módulos. Este diretório aponta para a tabela de endereços de exportação (EAT), que lista todos os símbolos exportados.",
        "purpose": "Permitir que outros módulos importem funções e dados deste executável",
        "security_notes": "Crítico para triagem de malware — procure funções exportadas só por ordinal, nomes duplicados ou exportações que encaminham direto para DLLs do sistema (comum em DLL sideloading). Exportações inesperadas (especialmente rede, injeção de processo ou rotinas de serviço) podem indicar C2 ou persistência.",
    },
    "Import Directory": {
        "title": "Diretório de Importação",
        "description": "Lista todos os módulos e funções que este executável importa de outros módulos. Cada entrada de importação especifica o nome do módulo e as funções importadas.",
        "purpose": "Resolver dependências de funções e bibliotecas externas em tempo de execução",
        "security_notes": "Revise DLLs e APIs importadas em busca de comportamento suspeito: imports diretos de WriteProcessMemory, CreateRemoteThread, VirtualAllocEx, syscalls Nt* ou DLLs incomuns (dbghelp, samsrv, wininet) costumam revelar capacidades de malware. Poucos imports com alta entropia no ponto de entrada geralmente indicam empacotamento ou resolução dinâmica de APIs.",
    },
    "Resource Directory": {
        "title": "Diretório de Recursos",
        "description": "Contém recursos do aplicativo, como ícones, bitmaps, strings e informações de versão. Os recursos são organizados em uma estrutura hierárquica.",
        "purpose": "Armazenar recursos e assets do aplicativo para uso em tempo de execução",
        "security_notes": "Verifique recursos ocultos, conteúdo embutido suspeito ou recursos que possam conter código malicioso",
    },
    "Exception Directory": {
        "title": "Diretório de Exceções",
        "description": "Contém informações de tratamento de exceções do executável. Este diretório é usado pelo mecanismo Structured Exception Handling (SEH) do Windows.",
        "purpose": "Tratar exceções e erros em tempo de execução de forma controlada",
        "security_notes": "Verifique handlers de exceção que possam ser usados para anti-debug ou técnicas de injeção de código",
    },
    "Certificate Directory": {
        "title": "Diretório de Certificado",
        "description": "Contém informações de assinatura digital e certificados para assinatura de código. Isso verifica a autenticidade e integridade do executável.",
        "purpose": "Verificar a identidade do publicador do software e garantir que o código não foi alterado",
        "security_notes": "Crítico para segurança — executáveis não assinados ou certificados inválidos podem indicar software malicioso",
    },
    "Base Relocation Directory": {
        "title": "Diretório de Relocação Base",
        "description": "Contém informações de relocação para quando o executável precisa ser carregado em um endereço base diferente do preferido.",
        "purpose": "Permitir que o carregador realoque o executável para endereços de memória diferentes, se necessário",
        "security_notes": "Verifique relocações excessivas que possam indicar tentativas de bypass de ASLR ou comportamento de carregamento suspeito",
    },
    "Debug Directory": {
        "title": "Diretório de Debug",
        "description": "Contém informações de debug, como números de linha, tabelas de símbolos e outros dados de depuração. Usado por debuggers e ferramentas de desenvolvimento.",
        "purpose": "Fornecer informações de depuração para desenvolvimento e troubleshooting",
        "security_notes": "Informações de debug podem revelar a estrutura interna — presença ou ausência pode indicar ofuscação ou remoção intencional",
    },
    "Architecture Directory": {
        "title": "Diretório de Arquitetura",
        "description": "Contém dados e informações específicas de arquitetura. Usado para arquiteturas especializadas ou recursos estendidos.",
        "purpose": "Fornecer funcionalidade e dados específicos da arquitetura",
        "security_notes": "Verifique dados de arquitetura inesperados que possam indicar compilação cruzada ou modificações suspeitas",
    },
    "Global Pointer Directory": {
        "title": "Diretório de Ponteiro Global",
        "description": "Contém informações sobre ponteiros globais usados pelo executável. Usado principalmente em arquiteturas RISC.",
        "purpose": "Gerenciar referências de ponteiro global para acesso eficiente à memória",
        "security_notes": "Uso incomum de ponteiro global pode indicar padrões suspeitos de acesso à memória",
    },
    "TLS Directory": {
        "title": "Diretório TLS",
        "description": "Contém informações de Thread Local Storage (TLS). O TLS permite que cada thread tenha sua própria cópia de certas variáveis.",
        "purpose": "Fornecer armazenamento específico por thread para aplicativos multithread",
        "security_notes": "Verifique callbacks TLS que possam ser usados para anti-debug ou inicialização de código malicioso",
    },
    "Load Configuration Directory": {
        "title": "Diretório de Configuração de Carga",
        "description": "Contém informações de configuração de como o executável deve ser carregado, incluindo recursos de segurança como Control Flow Guard e SEHOP.",
        "purpose": "Configurar recursos de segurança e comportamento de carregamento",
        "security_notes": "Crítico para análise de segurança — verifique recursos de segurança desativados que possam indicar intenção maliciosa",
    },
    "Bound Import Directory": {
        "title": "Diretório de Importação Vinculada",
        "description": "Contém informações de importação pré-vinculada (bound import) que podem acelerar o carregamento evitando resolução em tempo de execução.",
        "purpose": "Otimizar desempenho de carregamento pré-vinculando imports",
        "security_notes": "Verifique imports vinculados que possam ocultar comportamento suspeito de importação",
    },
    "Import Address Table Directory": {
        "title": "Diretório da Tabela de Endereços de Importação",
        "description": "Contém a Import Address Table (IAT), que armazena os endereços reais das funções importadas após serem resolvidas em tempo de execução.",
        "purpose": "Armazenar endereços resolvidos de funções importadas para chamadas eficientes",
        "security_notes": "Verifique hooking da IAT ou resolução suspeita de imports que possam indicar injeção de código",
    },
    "Delay Import Directory": {
        "title": "Diretório de Importação Diferida",
        "description": "Contém informações sobre funções importadas, mas não resolvidas até a primeira chamada. Pode melhorar o desempenho na inicialização.",
        "purpose": "Adiar a resolução de imports até que as funções sejam realmente necessárias",
        "security_notes": "Verifique imports diferidos que possam ocultar comportamento suspeito até o runtime",
    },
    "COM+ Runtime Header Directory": {
        "title": "Diretório de Cabeçalho COM+ Runtime",
        "description": "Contém informações e metadados do runtime COM+. Usado por aplicativos e serviços COM+.",
        "purpose": "Fornecer suporte ao runtime COM+ e metadados para aplicativos COM+",
        "security_notes": "Verifique dados COM+ que possam ser usados para hijacking COM ou criação suspeita de objetos COM",
    },
    "Reserved": {
        "title": "Diretório Reservado",
        "description": "Reservado para uso futuro pela Microsoft. Esta entrada de diretório não é usada atualmente, mas pode ser definida em versões futuras do Windows.",
        "purpose": "Reservado para recursos e extensões futuras do Windows",
        "security_notes": "Verifique qualquer dado em diretórios reservados — pode indicar recursos experimentais ou suspeitos",
    },
}


def leaf_keys(d, prefix=""):
    out = set()
    for k, v in d.items():
        p = k if not prefix else f"{prefix}|{k}"
        if isinstance(v, dict):
            out |= leaf_keys(v, p)
        else:
            out.add(p)
    return out


def main():
    data = json.loads(PT_PATH.read_text(encoding="utf-8"))
    pt = data["pt"]
    for key, val in TRANSLATIONS.items():
        if key not in pt:
            pt[key] = val
    data["pt"] = pt
    PT_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    en = json.loads((ROOT / "explanations.json").read_text(encoding="utf-8"))["en"]
    missing = leaf_keys(en) - leaf_keys(pt)
    print(f"Missing leaf keys after patch: {len(missing)}")


if __name__ == "__main__":
    main()
