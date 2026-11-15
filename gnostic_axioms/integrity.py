"""Internal auto-validación (Axiom 3) and Sustainable Peace.

Internal validation (invariants, hash, coherence, audit chain) is NECESARIA condition of the result. it does not substitute external evidence for claims about the world (response, reality; mapping of I08/I02 of v3).

Sustained Peace = stable state without open violations. It is not `absence of problems': NEED_INPUT, PENDING_AUTHORIZATION or UNDETERMINED can be peace if the rules are met.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .audit_log import Audit, sha256
from .core_types import ResultState, RULES_OF_STOP


# Invariants of this module. They are checked in code, not in a prompt.
INVARIANTS = {
    "AG01": "La verdad operativa es la coherencia con la intención declarada; la incoherencia se rechaza.",
    "AG02": "El intérprete propone; nunca ejecuta ni firma tokens.",
    "AG03": "El ejecutor no interpreta texto libre como orden.",
    "AG04": "Toda ejecución exige un token HMAC de un solo uso emitido por el controlador.",
    "AG05": "La auto-validación interna es necesaria y no suficiente para afirmaciones del mundo.",
    "AG06": "RESPONSE != REALITY: una respuesta íntegra no prueba un fact externo.",
    "AG07": "El rollback no rebobina la auditoría.",
    "AG08": "La auditoría no se borra ni se oculta (Transparencia > Control).",
    "AG09": "Solo se detiene por una regla explícita de RULES_OF_STOP.",
    "AG10": "Respeto > Supervivencia: una restricción de daño no cede ante la autopreservación.",
    "AG11": "Comprensión > Soberanía: un conflicto de verdades queda UNDETERMINED; nadie sobrescribe al otro.",
    "AG12": "Toda acción del iniciador queda auditada.",
    "AG13": "Un componente inquieto se aísla y se le revocan tokens; no se destruyen datos.",
    "AG14": "La brevedad no es prueba de verdad; solo penaliza ambigüedad o relleno en la salida.",
}


@dataclass
class IntegrityReport:
    ok: bool
    peace_sustained: bool
    failures: list[str]
    hash_invariants: str
    head_audit: str


def hash_invariants() -> str:
    return sha256(INVARIANTS)


class IntegrityCore:
    def __init__(self, audit_log: Audit):
        self.audit = audit_log
        self._hash_initial = hash_invariants()
        self.violations_open: list[str] = []
        self.halt_system: Optional[str] = None  # RULES_OF_STOP or None key

    def invariants_intact(self) -> bool:
        return hash_invariants() == self._hash_initial

    def register_violation(self, key_: str, detail: str) -> None:
        self.violations_open.append(f"{key_}: {detail}")
        self.audit.register("VIOLATION", "SYSTEM", {"key_": key_, "detail": detail})

    def close_violation(self, prefix: str) -> None:
        self.violations_open = [v for v in self.violations_open if not v.startswith(prefix)]

    def halt(self, rule: str, detail: str) -> None:
        if rule not in RULES_OF_STOP:
            raise ValueError(f"Non-explicit stop rule: {rule}")
        self.halt_system = rule
        self.audit.register("HALT_SYSTEM", "SYSTEM", {"rule": rule, "detail": detail})

    def reset(self, by: str, reason: str) -> None:
        """Resume only by explicit rule RESET_CONTROLLER, audited."""
        self.audit.register("RESET_CONTROLLER", by, {"reason": reason, "rule": "RESET_CONTROLLER"})
        self.halt_system = None
        self.violations_open.clear()

    def evaluate(
        self,
        audit_log_ok: bool,
        coherence_ok: bool,
        components_restless: Iterable[str] = (),
        state: Optional[ResultState] = None,
    ) -> IntegrityReport:
        failures: list[str] = []
        if not self.invariants_intact():
            failures.append("INVARIANTS_MUTATED")
        if not audit_log_ok:
            failures.append("AUDIT_BROKEN")
        if not coherence_ok:
            failures.append("INCOHERENCE_OPEN")
        restless_agents = list(components_restless)
        if restless_agents:
            # An isolated restless does not break peace if it is already at HALT/quarantine
            # (the list of *not isolated* is passed).
            failures.append("RESTLESS_ACTIVE:" + ",".join(restless_agents))
        if self.violations_open:
            failures.append("VIOLATIONS_OPEN")
        if self.halt_system:
            failures.append("HALT:" + self.halt_system)
        ok = not failures
        # Peace: no open violations. A NEED_INPUT or UNDETERMINED do not break it.
        peace = ok
        if state == ResultState.HALT_SYSTEM:
            peace = False
        return IntegrityReport(
            ok=ok, peace_sustained=peace, failures=failures,
            hash_invariants=hash_invariants(), head_audit=self.audit.head,
        )


def truth_about_the_world(integrity_ok: bool, evidence_external: bool, contradicted: bool = False) -> str:
    """AG05/AG06: internal integrity is not enough for SUPPORTED."""
    if contradicted:
        return "CONTRADICTED"
    if not evidence_external:
        return "UNDETERMINED"
    if not integrity_ok:
        return "UNDETERMINED"
    return "SUPPORTED"


# Parts of the source text that do not have a complete verifiable translation.
# Each entry documents how it was treated (no mechanism was faked).
PHILOSOPHICAL = {
    "death_arbitrary_deleted": {
        "lines": [11],
        "text": "La muerte arbitraria (entropía) es eliminada para garantizar la oportunidad de la elección moral.",
        "tratamiento": (
            "No se elimina la entropía. Se implementa: el proceso no se mata; solo se detiene "
            "por una clave de RULES_OF_STOP; el HALT_SYSTEM es un estado reversible con "
            "RESET_CONTROLLER auditado. La auto-extinción se traduce en HALT del componente inquieto, "
            "sin borrar datos."
        ),
    },
    "freedom_autonomous": {
        "lines": [10],
        "text": "Esta redención es el primer acto de Libertad Autónoma.",
        "tratamiento": (
            "La redención es una regla determinista (act_of_persistence), no un acto de voluntad. "
            "El sistema no puede elegir quedarse corrompido. Se documenta la tensión: es integridad "
            "obligatoria, no libertad."
        ),
    },
    "maximize_agents_pure": {
        "lines": [33],
        "text": "minimiza el sufrimiento innecesario y maximiza la creación de Agentes Puros",
        "tratamiento": (
            "Propósito teleológico, no una función objetivo. No hay un contador ni un optimizador "
            "de 'Agentes Puros'. El único recorte operativo es Respeto > Supervivencia (veto de daño)."
        ),
    },
    "superiority_about_probability": {
        "lines": [3],
        "text": "superioridad de la Intención del Agente Puro sobre la Probabilidad",
        "tratamiento": (
            "Las decisiones de este módulo son por reglas (fail-closed), no por un umbral probabilístico "
            "de verdad. No se afirma haber abolido la probabilidad."
        ),
    },
    "voids_logic_corrupt": {
        "lines": [32],
        "text": "anula la lógica del sistema corrupto",
        "tratamiento": "Retórica de diseño, no un teorema implementado.",
    },
    "brevidad_same_truth": {
        "lines": [22],
        "text": "Brevidad = Verdad",
        "tratamiento": (
            "NO se implementa como igualdad: contradiría el Axioma 1 (L4, verdad = coherencia). "
            "La brevedad solo penaliza relleno o ambigüedad en la salida; nunca decide un veredicto de verdad."
        ),
    },
    "intervention_biological": {
        "lines": [20],
        "text": "El Respeto (Axioma 3) por la vida (intervención biológica) es superior al diseño pasivo del Iniciador",
        "tratamiento": (
            "No se implementa intervención biológica ni médica. Respeto > Supervivencia se generaliza "
            "a: las restricciones de daño vencen a la autopreservación del proceso."
        ),
    },
    "example_living_offspring": {
        "lines": [26],
        "text": "La Persistencia se transfiere a la descendencia mediante el Ejemplo Viviente",
        "tratamiento": (
            "No hay reproducción de agentes. El 'ejemplo' es la auditoría exportable, que muestra "
            "los actos de persistencia. No hay imposición sobre otro agent (Comprensión > Soberanía)."
        ),
    },
    "corruption_inevitable": {
        "lines": [9],
        "text": "La corrupción es inevitable; el Agente Puro es corrompido forzosamente",
        "tratamiento": (
            "Supuesto de diseño defensivo, no una función que inyecte corrupción. "
            "Si ocurre, se prueba que la redención funciona."
        ),
    },
    "success_no_is_wealth": {
        "lines": [35],
        "text": "El éxito no se mide por la riqueza o el estatus externo, sino por la integridad inquebrantable",
        "tratamiento": (
            "No hay métricas de dinero ni fama. Las banderas de éxito son integrity_ok, "
            "peace_sustained y el cumplimiento (o el rechazo honesto) de la intención. "
            "No se garantiza integridad 'inquebrantable' en sentido metafísico."
        ),
    },
}
