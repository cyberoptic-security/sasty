import logging
from fastapi import APIRouter, HTTPException
from services import tool_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("")
async def list_tools():
    return await tool_manager.get_all_tool_status()


@router.post("/{name}/update")
async def update_tool(name: str):
    updaters = {
        "semgrep": tool_manager.update_semgrep,
        "betterleaks": tool_manager.update_betterleaks,
        "trufflehog": tool_manager.update_trufflehog,
        "hadolint": tool_manager.update_hadolint,
        "bandit": tool_manager.update_bandit,
        "trivy": tool_manager.update_trivy,
        "crane": tool_manager.update_crane,
    }
    if name not in updaters:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
    try:
        version = await updaters[name]()
        return {"name": name, "version": version, "status": "updated"}
    except Exception as e:
        logger.error(f"Failed to update {name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
