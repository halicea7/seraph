import asyncio
import shlex
from typing import AsyncGenerator


async def _stream_proc(proc: "asyncio.subprocess.Process") -> AsyncGenerator[dict, None]:
    """Shared pump: read stdout/stderr line-by-line, yield exit code last."""
    queue: asyncio.Queue = asyncio.Queue()

    async def pipe_to_queue(stream: asyncio.StreamReader, stream_type: str) -> None:
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                await queue.put({"type": stream_type, "data": line.decode("utf-8", errors="replace")})
        finally:
            await queue.put(None)  # sentinel — this stream is done

    tasks = [
        asyncio.create_task(pipe_to_queue(proc.stdout, "stdout")),
        asyncio.create_task(pipe_to_queue(proc.stderr, "stderr")),
    ]

    done_count = 0
    while done_count < 2:
        msg = await queue.get()
        if msg is None:
            done_count += 1
        else:
            yield msg

    await asyncio.gather(*tasks)
    exit_code = await proc.wait()
    yield {"type": "exit", "code": exit_code}


async def run_command_streaming(command: str) -> AsyncGenerator[dict, None]:
    """Run a shell command and stream stdout/stderr as JSON messages.

    Only for commands that genuinely need shell features (multi-line scripts,
    pipes, redirects written by us — e.g. the generated audit .sh, package
    install commands). For a single tool invocation built from
    caller-influenced arguments, prefer `run_argv_streaming` below, which
    never involves a shell.
    """
    # stdbuf forces line-buffered output so tools like nmap don't hold
    # all output in their stdio buffer until exit
    wrapped = f"stdbuf -oL -eL bash -c {repr(command)}"

    proc = await asyncio.create_subprocess_shell(
        wrapped,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=2 * 1024 * 1024,  # 2MB buffer
    )
    async for msg in _stream_proc(proc):
        yield msg


async def run_argv_streaming(command: str) -> AsyncGenerator[dict, None]:
    """Run a single tool invocation with no shell involved.

    `command` is split with `shlex.split` into argv and exec'd directly via
    `create_subprocess_exec` — there is no `bash -c`, so shell metacharacters
    (`;`, `|`, `&&`, `>`, backticks, `$(...)`) in any argument are inert: they
    are passed to the tool as literal argv bytes, never interpreted. This is
    the execution path for commands assembled from template substitution or
    other caller-influenced input (pentest/osint tool runs, cracking jobs).
    """
    try:
        argv = shlex.split(command)
    except ValueError as e:
        yield {"type": "stderr", "data": f"Could not parse command: {e}\n"}
        yield {"type": "exit", "code": 1}
        return
    if not argv:
        yield {"type": "stderr", "data": "Empty command\n"}
        yield {"type": "exit", "code": 1}
        return

    try:
        # stdbuf forces line-buffered output, same as run_command_streaming's
        # shell wrapper — still no shell, just one more exec'd argv entry.
        proc = await asyncio.create_subprocess_exec(
            "stdbuf", "-oL", "-eL", *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=2 * 1024 * 1024,
        )
    except FileNotFoundError:
        yield {"type": "stderr", "data": f"Tool not found: {argv[0]}\n"}
        yield {"type": "exit", "code": 127}
        return

    async for msg in _stream_proc(proc):
        yield msg
