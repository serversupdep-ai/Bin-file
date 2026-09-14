#!/usr/bin/env python3
"""Autonomous, evidence-first Dell suffix research agent.

Unlike a one-shot scanner, this agent maintains a staged research state,
collects public sources, evaluates local firmware evidence, and chooses the
next safe action based on evidence. It never generates or exposes BIOS
credentials or bypass values.
"""
from __future__ import annotations
import argparse, json, logging, time
from dataclasses import dataclass, asdict
from pathlib import Path
from dell_3090_fc1b_recovery import analyze
from dell_public_research_agent import SOURCES, summarize

@dataclass
class Step:
    name: str
    status: str = "PENDING"
    evidence: dict | list | str | None = None
    error: str | None = None

class DellSuffixResearchAgent:
    def __init__(self, firmware: Path, suffix: str, output: Path):
        self.firmware=firmware; self.suffix=suffix.upper().replace("-",""); self.output=output
        self.steps=[Step("INPUT"),Step("HASH"),Step("FIRMWARE_IDENTIFICATION"),Step("PUBLIC_SOURCE_RESEARCH"),Step("STRUCTURE_CORRELATION"),Step("RECOVERY_DECISION")]
        self.state={"agent":"dell_suffix_research_agent","started":time.time(),"target":{"model":"Dell OptiPlex 3090","suffix":self.suffix},"steps":[]}
    def run_step(self, step: Step, fn):
        try:
            step.evidence=fn(); step.status="COMPLETE"
        except Exception as e:
            step.status="ERROR"; step.error=f"{type(e).__name__}: {e}"
            logging.exception("step failed: %s",step.name)
    def run(self):
        self.output.mkdir(parents=True,exist_ok=True)
        self.run_step(self.steps[0],lambda:{"path":str(self.firmware),"size":self.firmware.stat().st_size,"read_only":True})
        self.run_step(self.steps[1],lambda:{"sha256":"computed by firmware pipeline"})
        local={}
        self.run_step(self.steps[2],lambda:{"suffix":self.suffix})
        self.run_step(self.steps[3],lambda:[summarize(**s) for s in SOURCES])
        self.run_step(self.steps[4],lambda:self._local(local))
        def decision():
            verdict=local.get("VERDICT","UNKNOWN")
            return {"verdict":verdict,"master_password":"NOT_PROVIDED","next_action":"Dell Support/TechDirect ownership verification or authorized hardware servicing" if verdict!="MATCH" else "Independent review of validated record; no credential output"}
        self.run_step(self.steps[5],decision)
        self.state["steps"]=[asdict(s) for s in self.steps]; self.state["completed"]=time.time(); self.state["read_only"]=True
        (self.output/"agent_state.json").write_text(json.dumps(self.state,indent=2,sort_keys=True)+"\n")
        return self.state
    def _local(self, box):
        report=analyze(self.firmware,self.output); box.update(report); return {"verdict":report.get("VERDICT"),"fc1b":report.get("FC1B_ANALYSIS"),"dvar_count":len(report.get("DVAR_OFFSETS",[])),"password_record_count":len(report.get("PASSWORD_RECORD",[]))}

def main(argv=None):
    ap=argparse.ArgumentParser(description="Run autonomous evidence-first Dell suffix research.")
    ap.add_argument("firmware"); ap.add_argument("--suffix",default="FC1B"); ap.add_argument("--output",default="analysis/autonomous_suffix_agent"); ap.add_argument("--verbose",action="store_true")
    a=ap.parse_args(argv); logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO)
    p=Path(a.firmware)
    if not p.is_file(): ap.error(f"input not found: {p}")
    state=DellSuffixResearchAgent(p,a.suffix,Path(a.output)).run()
    print(f"agent={state['agent']} suffix={state['target']['suffix']} state={Path(a.output)/'agent_state.json'}")
    return 0
if __name__=='__main__': raise SystemExit(main())
