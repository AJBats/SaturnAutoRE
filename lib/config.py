"""Project configuration loader for auto_re pipeline."""

import os
import yaml


DEFAULT_CONFIG_PATH = "workstreams/auto_re/config.yaml"

# SaturnAutoRE repo root — where the shared tooling lives
HARNESS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEDNAFEN_DIR = os.path.join(HARNESS_DIR, "mednafen")


def load_config(project_dir=None):
    """Load project config from workstreams/auto_re/config.yaml.

    If project_dir is None, uses current working directory.
    Returns a dict with resolved paths.
    """
    if project_dir is None:
        project_dir = os.getcwd()

    config_path = os.path.join(project_dir, DEFAULT_CONFIG_PATH)
    if not os.path.exists(config_path):
        return None

    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Inject resolved paths
    config["_project_dir"] = project_dir
    config["_harness_dir"] = HARNESS_DIR
    config["_mednafen_dir"] = MEDNAFEN_DIR
    config["_auto_re_dir"] = os.path.join(project_dir, "workstreams", "auto_re")
    config["_observations_dir"] = os.path.join(project_dir, "workstreams", "auto_re", "observations")
    config["_claims_dir"] = os.path.join(project_dir, "workstreams", "auto_re", "claims")
    config["_results_path"] = os.path.join(project_dir, "workstreams", "auto_re", "results.tsv")
    config["_priorities_path"] = os.path.join(project_dir, "workstreams", "auto_re", "explorer_priorities.md")
    config["_mission_path"] = os.path.join(project_dir, "workstreams", "auto_re", "mission.md")
    config["_reviews_dir"] = os.path.join(project_dir, "workstreams", "auto_re", "reviews")
    config["_samples_dir"] = os.path.join(project_dir, "build", "samples")

    # Resolve save state paths relative to project
    for name, state in config.get("save_states", {}).items():
        if "file" in state and not os.path.isabs(state["file"]):
            state["_resolved_path"] = os.path.join(project_dir, state["file"])

    # Resolve CUE path relative to project
    cue = config.get("cue_path", "")
    if cue and not os.path.isabs(cue):
        config["_cue_path"] = os.path.join(project_dir, cue)
    else:
        config["_cue_path"] = cue

    return config


def get_car_struct_base(config):
    """Return car struct base address as int."""
    val = config.get("car_struct", {}).get("base", 0)
    if isinstance(val, str):
        return int(val, 16)
    return val


def get_assembly_dir(config):
    """Return absolute path to assembly source directory."""
    rel = config.get("assembly_dir", "src")
    return os.path.join(config["_project_dir"], rel)


def get_button(config, role):
    """Get the button name for a role (throttle, brake, steer_left, steer_right)."""
    return config.get("controls", {}).get(role, "")
