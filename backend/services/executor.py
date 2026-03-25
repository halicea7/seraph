import asyncio
from typing import AsyncGenerator


async def run_command_streaming(command: str) -> AsyncGenerator[dict, None]:
    """Run a shell command and stream stdout/stderr as JSON messages."""
    # stdbuf forces line-buffered output so tools like nmap don't hold
    # all output in their stdio buffer until exit
    wrapped = f"stdbuf -oL -eL bash -c {repr(command)}"

    proc = await asyncio.create_subprocess_shell(
        wrapped,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=2 * 1024 * 1024,  # 2MB buffer
    )

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
