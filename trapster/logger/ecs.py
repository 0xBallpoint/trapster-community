from .output import OutputLogger


class EcsLogger(OutputLogger):
    def __init__(
        self,
        node_id,
        service_name="Trapster",
        service_version=None,
        environment=None,
        host_name=None,
        observer_name="Trapster",
        logfile=None,
        mode="a",
        ecs_version="8.11.0",
    ):
        output = "file" if logfile else "terminal"
        output_kwargs = {"logfile": logfile, "mode": mode} if logfile else {}
        format_kwargs = {
            "service_version": service_version,
            "environment": environment,
            "host_name": host_name,
            "observer_name": observer_name,
            "ecs_version": ecs_version,
        }
        super().__init__(
            node_id=node_id,
            output=output,
            event_format="ecs",
            output_kwargs=output_kwargs,
            format_kwargs=format_kwargs,
        )
