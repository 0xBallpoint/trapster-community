from .output import OutputLogger


class FileLogger(OutputLogger):
    def __init__(
        self,
        node_id,
        logfile="/var/log/trapster-community.log",
        mode="w+",
        event_format="default",
        format_kwargs=None,
    ):
        super().__init__(
            node_id=node_id,
            output="file",
            event_format=event_format,
            output_kwargs={"logfile": logfile, "mode": mode},
            format_kwargs=format_kwargs or {},
        )
