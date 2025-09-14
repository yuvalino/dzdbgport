from __future__ import annotations

import os
import asyncio
import logging
import struct
import sys
import json
import datetime
import argparse
import websockets

from contextvars import ContextVar
from contextlib import AsyncExitStack

from pathlib import Path

from dataclasses import dataclass, field

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text

# in recompilation our side sends this:

# 0b 00 00 00
# 00 00 00 00
# 01 00 00 00
# 70 5b dd 27 40 02 00 00
# 2b 07 00 00

# other side returns this log:
# SCRIPT    (E): y/mounts/framework/scripts/4_World/entities/manbase/modded_playerbase.c(8): error: Unknown type 'PlayerBase'

# then sends
# 05 00 00 00
# 00 00 00 00
# 70 5b dd 27 40 02 00 00

# then does a full data dump like earlier (that starts with 04 00 00 00 u32)

# and then logs this:
# SCRIPT       : ScriptDebugger: remote re-compilation was successful.
 
# then we send

# 09 00 00 00
# 00 00 00 00
# 00 00 00 00
# 08 00 00 00
# 00 00 00 00


DZDEBUGPORTS = [1000, 1001]
WSPORT = 28051
LOGFILE = Path(".") / "dayzdebug.log"

PEERTYPE_CLIENT = "C"
PEERTYPE_SERVER = "S"


# major/minor/hotfix
VERSION = [0,3,0]


task_prefix = ContextVar("task_prefix", default="")


class ConsoleInterface:
    def __init__(self, ps1: str = "dz$ "):
        self.session = PromptSession()
        self.command_handlers = {}
        self.ps1 = ps1

        self.register_command("help", self.cmd_help)
        self.register_command("echo", self.cmd_echo)

    def register_command(self, name, handler):
        self.command_handlers[name] = handler

    async def run(self):
        with patch_stdout():
            while True:
                try:
                    text = await self.session.prompt_async(f"{self.ps1}")
                    await self.handle_command(text)
                except (EOFError, KeyboardInterrupt):
                    print("~console")
                    break

    async def handle_command(self, text: str):
        stripped = text.strip()
        if not stripped:
            return

        parts = stripped.split()
        cmd = parts[0]
        args = parts[1:]

        handler = self.command_handlers.get(cmd)
        if not handler:
            print(f"ERROR: unknown command '{cmd}', try 'help'")
            return

        try:
            await handler(args)
        except Exception as e:
            print(f"ERROR: {cmd}: {str(e)}")

    async def cmd_help(self, args):
        print("console commands:")
        commands = sorted(self.command_handlers.keys())

        line = "  "  # Start with indent
        max_len = 50
        for cmd in commands:
            if len(line) + len(cmd) + 2 > max_len:
                print(line.rstrip())
                line = "  "  # Reset with indent
            line += cmd + "  "
        if line.strip():
            print(line.rstrip())
    
    async def cmd_echo(self, args):
        print(f"{' '.join(args)}")


class SocketBuffer:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, log_dir: Path | None = None):
        self.read_offset = 0
        self.reader = reader
        self.writer = writer  # NEW
        self.buffer = bytearray()
        self.data_event = asyncio.Event()
        self.closed = False
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

        if log_dir:
            self.raw_log = (log_dir / "data.bin.txt").open("wb")
            self.format_log = (log_dir / "data.format.txt").open("w", encoding="utf-8")
        else:
            self.raw_log = self.format_log = None

    async def start(self):
        try:
            while not self.closed:
                data = await self.reader.read(4096)
                if not data:
                    logging.info("Connection closed by peer.")
                    break
                self._log_received(data)
                self._store(data)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            logging.info("Connection closed by peer.")
        except OSError as e:
            if e.winerror == 64:
                logging.info("Connection closed by peer.")
            else:
                logging.error(f"Socket read error: {e}")
        except Exception as e:
            logging.error(f"Unexpected socket read error: {e}")
        finally:
            self.close()

    def _log_received(self, data: bytes):
        if self.raw_log:
            self.raw_log.write(data)
            self.raw_log.flush()

        if self.format_log:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            self.format_log.write(f"{timestamp} [RECV] 0x{len(data):X} {repr(data)}\n")
            self.format_log.flush()

    def _store(self, data: bytes):
        self.buffer.extend(data)
        self.data_event.set()

    async def read(self, n: int, timeout: float | None = None) -> bytes:
        if timeout is None:
            timeout = 10.0
        elif timeout == 0:
            timeout = None
        
        try:
            async with self.read_lock:
                while len(self.buffer) < n:
                    if self.closed:
                        raise EOFError(f"Socket closed. Needed {n} bytes, got {len(self.buffer)}.")
                    self.data_event.clear()
                    await asyncio.wait_for(self.data_event.wait(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Timed out waiting for {n} bytes, only got {len(self.buffer)}")

        data = self.buffer[:n]
        del self.buffer[:n]
        self.read_offset += n
        return data

    def _log_sent(self, data: bytes):
        if self.format_log:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            self.format_log.write(f"{timestamp} [SENT] 0x{len(data):X} {repr(data)}\n")
            self.format_log.flush()

    async def write(self, data: bytes):
        async with self.write_lock:
            self.writer.write(data)
            await self.writer.drain()
        self._log_sent(data)

    def close(self):
        self.closed = True
        if self.raw_log:
            self.raw_log.close()
        if self.format_log:
            self.format_log.close()
        self.data_event.set()
    
    def tell(self):
        return self.read_offset


DZ_MESSAGE_REGISTRY: dict[int, type[DZBaseMsg]] = {}


class DayZProtocol:
    def __init__(self, buffer: SocketBuffer):
        self.buffer = buffer
        self.wlock = asyncio.Lock()

    # === Read helpers ===

    async def readraw(self, n: int, timeout: float | None = None) -> bytes:
        """Direct read of `n` bytes from buffer."""
        return await self.buffer.read(n, timeout=timeout)

    async def readstruct(self, fmt: str, timeout: float | None = None):
        """Read and unpack a struct with the given format string."""
        size = struct.calcsize(fmt)
        data = await self.readraw(size, timeout=timeout)
        return struct.unpack(fmt, data)

    async def readu32(self, timeout: float | None = None) -> int:
        """Read a little-endian unsigned 32-bit int."""
        (val,) = await self.readstruct("<I", timeout=timeout)
        return val

    async def readu64(self, timeout: float | None = None) -> int:
        """Read a little-endian unsigned 64-bit int."""
        (val,) = await self.readstruct("<Q", timeout=timeout)
        return val

    async def readbuffer(self, timeout: float | None = None) -> bytes:
        """Read a length-prefixed buffer (uint32 length + bytes)."""
        length = await self.readu32(timeout=timeout)
        if length == 0:
            return b""
        return await self.readraw(length, timeout=timeout)

    async def readcstr(self, timeout: float | None = None) -> str:
        """Read a length-prefixed buffer and decode as UTF-8 string."""
        buf = await self.readbuffer(timeout=timeout)
        if buf.endswith(b"\x00"):
            buf = buf[:-1]
        return buf.decode("utf-8", errors="replace")

    # === Write helpers ===

    async def writeraw(self, data: bytes):
        """Write raw bytes directly to the buffer."""
        await self.buffer.write(data)

    async def writestruct(self, fmt: str, *values):
        """Pack and write a struct with the given format string."""
        data = struct.pack(fmt, *values)
        await self.writeraw(data)

    async def writeu32(self, value: int):
        """Write a little-endian unsigned 32-bit int."""
        await self.writestruct("<I", value)

    async def writeu64(self, value: int):
        """Write a little-endian unsigned 64-bit int."""
        await self.writestruct("<Q", value)

    async def writebuffer(self, data: bytes):
        """Write a length-prefixed buffer (uint32 length + bytes)."""
        await self.writeu32(len(data))
        if data:
            await self.writeraw(data)

    async def writecstr(self, text: str):
        """Write a UTF-8 encoded string with null terminator and length prefix."""
        encoded = text.encode("utf-8")
        await self.writebuffer(encoded)

    # === Parse ===
    
    async def parse_next(self, timeout=0) -> DZBaseMsg:
        start_offset = self.tell()
        tag = await self.readu32(timeout=timeout)
        if tag not in DZ_MESSAGE_REGISTRY:
            raise ValueError(f"Unknown tag {hex(tag)}")
        
        msg_class = DZ_MESSAGE_REGISTRY[tag]
        return await msg_class.decode(self)
    
    # === Send ===

    async def send(self, msg: DZBaseMsg):
        await msg.encode(self)

    # === Helpers ===
    
    def tell(self):
        return self.buffer.tell()


def dzmsg(cls):
    if not hasattr(cls, "tag"):
        raise ValueError(f"{cls.__name__} must define a `tag` class attribute.")
    tag = cls.tag
    if tag in DZ_MESSAGE_REGISTRY:
        raise ValueError(f"Duplicate tag {tag:#x} registered for {cls.__name__}")
    DZ_MESSAGE_REGISTRY[tag] = cls
    return cls


PROTO_DZ_INVALID   = 0x0
PROTO_DZ_HELLO     = 0x1
PROTO_DZ_EXIT      = 0x2
PROTO_DZ_BLOCK     = 0x4
PROTO_DZ_UNBLOCK   = 0x5
PROTO_DZ_EXEC      = 0xA
PROTO_DZ_RECOMPILE = 0xB
PROTO_DZ_LOG       = 0x14


@dzmsg
@dataclass
class DZBaseMsg:
    tag = PROTO_DZ_INVALID

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZBaseMsg:
        raise NotImplementedError()

    async def encode(self, proto: DayZProtocol):
        raise NotImplementedError()


@dzmsg
@dataclass
class DZHelloMsg(DZBaseMsg):
    tag = PROTO_DZ_HELLO
    game_pid: int

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZHelloMsg:
        assert 0x4 == await proto.readu32()
        game_pid = await proto.readu32()

        logging.info(f"[RECV] [HELLO    ] {game_pid=}")

        return cls(game_pid=game_pid)


@dzmsg
@dataclass
class DZExitMsg(DZBaseMsg):
    tag = PROTO_DZ_EXIT

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZExitMsg:
        assert 0x0 == await proto.readu32()

        logging.info(f"[RECV] [EXIT     ]")

        return cls()


@dzmsg
@dataclass
class DZBlockLoadMsg(DZBaseMsg):
    tag = PROTO_DZ_BLOCK
    block_id: int
    filenames: list[str]

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZBlockLoadMsg:
        assert 0 == await proto.readu32()
        block_id = await proto.readu64()
        filenames_count = await proto.readu32()
        pair_count = await proto.readu32()
        assert 0x0 == await proto.readu32()

        logging.info(f"[RECV] [BLOCK    ] block_id={hex(block_id)} files={filenames_count} {pair_count=}")

        # Read filenames
        filenames = []
        for _ in range(filenames_count):
            s = await proto.readcstr()
            filenames.append(s)

        # Read pairs
        pairs = []
        for _ in range(pair_count):
            a = await proto.readu32()
            b = await proto.readu32()
            pairs.append((a, b))

        return cls(block_id=block_id, filenames=filenames)


@dzmsg
@dataclass
class DZBlockUnloadMsg(DZBaseMsg):
    tag = PROTO_DZ_UNBLOCK
    block_id: int
    filenames: list[str] = field(default_factory=list)  # populated afterwards by DayZDebugPort before on_port_message()

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZBlockUnloadMsg:
        assert 0x0 == await proto.readu32()
        block_id = await proto.readu64()

        logging.info(f"[RECV] [UNBLOCK  ] block_id={hex(block_id)}")

        return cls(block_id=block_id, filenames=[])


@dzmsg
@dataclass
class DZExecCodeMsg(DZBaseMsg):
    tag = PROTO_DZ_EXEC
    module: str
    code: str

    async def encode(self, proto: DayZProtocol):
        logging.info(f"[SEND] [EXEC CODE] module=\"{self.module}\" code=\"{self.code}\"")
        async with proto.wlock:
            await proto.writeu32(PROTO_DZ_EXEC)
            await proto.writeu32(0)
            await proto.writecstr(self.module)
            await proto.writeu32(0)
            await proto.writecstr(self.code)


@dzmsg
@dataclass
class DZRecompileMsg(DZBaseMsg):
    tag = PROTO_DZ_RECOMPILE
    block_id: int
    file_index: int

    async def encode(self, proto: DayZProtocol):
        logging.info(f"[SEND] [RECOMPILE] block_id={hex(self.block_id)} file_index={hex(self.file_index)}")
        async with proto.wlock:
            await proto.writeu32(PROTO_DZ_RECOMPILE)
            await proto.writeu32(0)
            await proto.writeu32(1) # what is this? len?
            await proto.writeu64(self.block_id)
            await proto.writeu32(self.file_index)


@dzmsg
@dataclass
class DZLogMsg(DZBaseMsg):
    tag = PROTO_DZ_LOG
    data: str

    @classmethod
    async def decode(cls, proto: DayZProtocol) -> DZLogMsg:
        assert 0x0 == await proto.readu32()
        data = await proto.readcstr()

        logging.info(f"[RECV] [LOG      ] {data.rstrip()}")

        return cls(data=data)


class DayZPortListener:
    async def on_port_connected(self, port: DayZDebugPort):
        pass

    async def on_port_disconnected(self, port: DayZDebugPort):
        pass

    async def on_port_message(self, port: DayZDebugPort, msg: DZBaseMsg):
        pass


class DayZDebugPort:
    def __init__(self, addr, protocol: DayZProtocol, peer_type: str):
        self.addr = addr
        self.protocol = protocol
        self.running = True
        self.blocks: dict[int, DZBlockLoadMsg] = dict()
        self.pid = -1
        self.peer_type = peer_type
        
        self.listeners: dict[int, DayZPortListener] = dict()
        self.next_idx = 0
    
    def add_listener(self, listener: DayZPortListener) -> int:
        idx = self.next_idx
        self.listeners[idx] = listener
        self.next_idx += 1
        return idx

    async def recv_one_msg(self, timeout=0) -> DZBaseMsg:
        msg = await self.protocol.parse_next(timeout=timeout)
        await self.handle_msg(msg)
        return msg

    async def run(self):
        while self.running and not self.protocol.buffer.closed:
            try:
                await self.recv_one_msg()
            except EOFError as e:
                logging.info(f"Debug port closed")
                break
            except TimeoutError as e:
                logging.warning(f"Parser timeout: {e}")
                break
            except Exception as e:
                logging.exception(f"Unexpected parsing error: {e}")
                break
    
    async def handle_msg(self, msg: DZBaseMsg):
        match msg:
            case DZHelloMsg():
                self.pid = msg.game_pid
            case DZBlockLoadMsg():
                await self.load_block(msg)
            case DZBlockUnloadMsg():
                block = await self.unload_block(msg)
                # populate msg.filenames if possible
                if block:
                    msg.filenames = block.filenames
        
        for listener in self.listeners.values():
            await listener.on_port_message(self, msg)
    
    async def load_block(self, msg: DZBlockLoadMsg):
        if msg.block_id in self.blocks:
            logging.warning(f"duplicate block_id {hex(msg.block_id)}")
        self.blocks[msg.block_id] = msg
    
    async def unload_block(self, msg: DZBlockUnloadMsg) -> DZBlockLoadMsg | None:
        block = self.blocks.pop(msg.block_id, None)
        if not block:
            logging.warning(f"unknown block_id {hex(msg.block_id)}")
        return block

    def find_block_and_index_for_filename(self, filename: str) -> tuple[DZBlockLoadMsg, int]:
        for block_id, block in self.blocks.items():
            try:
                return block, block.filenames.index(filename)
            except Exception:
                continue
        
        raise ValueError(f"filename \"{filename}\" not found in loaded blocks")

    def search_filenames(self, name: str) -> list[tuple[DZBlockLoadMsg, int]]:
        results = []
        for block_id, block in self.blocks.items():
            for index, filename in enumerate(block.filenames):
                if name in filename:
                    results.append((block, index))
        return results

    async def exec_code(self, module: str, code: str):
        return await self.protocol.send(DZExecCodeMsg(module=module, code=code))

    async def recompile(self, block_id: int, file_index: int):
        return await self.protocol.send(DZRecompileMsg(block_id=block_id, file_index=file_index))


def dzcli(name=None, **kwargs):
    def decorator(func):
        func._is_command = True
        func._command_name = name or func.__name__.removeprefix("cmd_")
        func._attrs = kwargs
        return func
    return decorator


class DayZDebugConsole(DayZPortListener):
    def __init__(self, console: ConsoleInterface):
        self._ports: dict[int, DayZDebugPort] = {}
        self._selected_port: DayZDebugPort | None = None
        self.console = console
        self._register_commands()

    async def on_port_connected(self, port: DayZDebugPort):
        select_port = False
        if port.pid in self._ports:
            logging.warning(f"port pid:{port.pid} already connected, closing")
            if self._selected_port == self._ports[port.pid]:
                select_port = True  # select current port if previous one on same pid was selected
            self._ports[port.pid].close()
        elif not self._ports:
            assert not self._selected_port
            select_port = True  # select port if no ports available
        
        self._ports[port.pid] = port
        if select_port:
            self._selected_port = port
    
    async def on_port_disconnected(self, port: DayZDebugPort):
        if port.pid not in self._ports:
            logging.warning(f"port pid:{port.pid} disconnected but is not registered")
            return

        self._ports.pop(port.pid)

        if self._selected_port == port:
            self._selected_port = None

    def selected_port(self) -> DayZDebugPort:
        if not self._selected_port:
            raise ValueError(f"no port selected ({len(self._ports)} available)")
        return self._selected_port

    def _register_commands(self):
        for attr_name in dir(self):
            if attr_name.startswith("cmd_"):
                attr = getattr(self, attr_name)
                if callable(attr) and getattr(attr, "_is_command", False):
                    cmd_name = attr._command_name
                    def make_wrapper(attr):
                        def wrapper(args):
                            if attr._attrs.get("with_port"):
                                port = None
                                if len(args) and args[0].startswith("@"):
                                    port = self._ports[int(args[0][1:])]
                                    args = args[1:]
                                if not port:
                                    port = self.selected_port()
                                return attr(port, args)
                            return attr(args)
                        return wrapper
                    self.console.register_command(cmd_name, make_wrapper(attr))

    @dzcli()
    async def cmd_ports(self, args):
        print("connected debug ports:")
        if not self._ports:
            print(" - no connected ports")
            return
        
        found_selected = False
        def _peer_type_log(port: DayZDebugPort):
            return " S" if port.peer_type == PEERTYPE_SERVER else "C "
        for idx, port in enumerate(self._ports.values()):
            if self._selected_port == port:
                print(f">{idx+1}. [{_peer_type_log(port)}] pid={port.pid}")
                found_selected = True
            else:
                print(f" {idx+1}. [{_peer_type_log(port)}] pid={port.pid}")
        if not found_selected and self._selected_port:
            print(f">?. [{_peer_type_log(port)}] pid={port.pid}")
    
    @dzcli()
    async def cmd_select(self, args):
        if not args:
            if self._selected_port:
                print(self._selected_port.pid)
            return

        if args[0] == "-":
            self._selected_port = None
            return
        
        try:
            pid = int(args[0])
        except Exception:
            pid = None
        if pid not in self._ports:
            raise ValueError(f"unknown port pid {pid}")
        self._selected_port = self._ports[pid]
        
    @dzcli(with_port=True)
    async def cmd_diag(self, port: DayZDebugPort, args):
        offset = port.protocol.tell()
        print(f"protocol read offset: {offset}")
    
    @dzcli(with_port=True)
    async def cmd_eval(self, port: DayZDebugPort, args):
        EVAL_MODULES = ["Core", "GameLib", "Game", "World", "Mission"]
        module="World"
        if args:
            if args[0] == "-h" or args[0] == "--help":
                print(f"eval [" + "|".join(f"-"+x for x in EVAL_MODULES) + "] CODE...")
                return
            if args[0].startswith("-"):
                opt = args[0][1:]
                if opt in EVAL_MODULES:
                    module = opt
                    args = args[1:]
        
        await port.exec_code(module=module, code=' '.join(args))
    
    @dzcli(with_port=True)
    async def cmd_blocks(self, port: DayZDebugPort, args):
        print(f"loaded blocks:")
        for block in port.blocks.values():
            print(f"  {hex(block.block_id)} (files={len(block.filenames)})")
    
    @dzcli(with_port=True)
    async def cmd_search_file(self, port: DayZDebugPort, args):
        name = ' '.join(args)
        print(f"searching for filename \"{name}\"")
        results = port.search_filenames(name)
        
        if not results:
            print(" - no results")
            return

        print(f"showing {len(results)} results")
        for index, result in enumerate(results):
            block, file_index = result
            print(f" {index+1}. {hex(block.block_id)}::{hex(file_index)}  {block.filenames[file_index]}")

    @dzcli(with_port=True)
    async def cmd_recompile(self, port: DayZDebugPort, args):
        name = ' '.join(args)
        results = port.search_filenames(name)
        if not results:
            raise ValueError(f"no filenames matching \"{name}\"")
        for block, file_index in results:
            await port.recompile(block_id=block.block_id, file_index=file_index)


class WebSocketListener:
    async def on_websocket_connected(self, websocket: websockets.ServerConnection):
        pass

    async def on_websocket_disconnected(self, websocket: websockets.ServerConnection):
        pass

    async def on_websocket_message(self, websocket: websockets.ServerConnection, message: str):
        pass


class WebSocketServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.clients = set()
        self.listeners: dict[int, WebSocketListener] = dict()
        self.next_idx = 0

    def add_listener(self, listener: WebSocketListener) -> int:
        idx = self.next_idx
        self.listeners[idx] = listener
        self.next_idx += 1
        return idx

    async def _handler(self, websocket: websockets.ServerConnection):
        logging.info(f"Client connected: {websocket.remote_address}")
        self.clients.add(websocket)
        for listener in self.listeners.values():
            await listener.on_websocket_connected(websocket)

        try:
            async for message in websocket:
                for listener in self.listeners.values():
                    if await listener.on_websocket_message(websocket, message):
                        break
        except Exception:
            logging.exception(f"Client {websocket.remote_address} exception:")
        finally:
            logging.info(f"Client disconnected: {websocket.remote_address}")
            for listener in self.listeners.values():
                await listener.on_websocket_disconnected(websocket)
            self.clients.remove(websocket)

            await websocket.close()

    async def _on_message(self, websocket, message):
        # send to all handlers until someone returns True
        for handler in self.handlers.values():
            if handler(websocket, message):
                break

    async def broadcast(self, message: str):
        if self.clients:
            await asyncio.gather(*(client.send(message) for client in self.clients))

    async def run(self):
        logging.info(f"Running WebSocket server on ws://{self.host}:{self.port}")
        async with websockets.serve(self._handler, self.host, self.port):
            await asyncio.Future()  # run forever


class DayZDebugWebSocketServer(DayZPortListener, WebSocketListener):
    def __init__(self, server: WebSocketServer):
        self.server = server
        self.ports: dict[int, DayZDebugPort] = dict()

    def get_one_port(self, tcp_port: int | None) -> DayZDebugPort:
        if not self.ports or (tcp_port is not None and tcp_port not in self.ports):
            raise ValueError("Game port not connected" + "" if tcp_port is None else f" (tcp_port {tcp_port})")
        if tcp_port is None:
            return next(iter(self.ports.values()))
        return self.ports[tcp_port]

    def get_ports(self, tcp_port: int | None) -> list[DayZDebugPort]:
        if not self.ports or (tcp_port is not None and tcp_port not in self.ports):
            return []
        if tcp_port is not None:
            return [self.ports[tcp_port]]
        return list(self.ports.values())

    async def _send_or_broadcast(self, websocket: websockets.ServerConnection | None, message_json: dict):
        message = json.dumps(message_json)
        if websocket:
            await websocket.send(message)
        else:
            await self.server.broadcast(message)

    async def _send_ws_hello(self, websocket: websockets.ServerConnection | None):
        await self._send_or_broadcast(websocket, {
            "type": "hello",
            "version": VERSION,
            "pid": os.getpid(),
        })

    async def _send_ws_connect(self, websocket: websockets.ServerConnection | None, port: DayZDebugPort):
        await self._send_or_broadcast(websocket, {
            "type": "connect",
            "pid": port.pid,
            "tcp_port": port.addr[1],
            "peer_type": port.peer_type,
        })
    
    async def _send_ws_disconnect(self, websocket: websockets.ServerConnection | None, port: DayZDebugPort, reason: str):
       await self._send_or_broadcast(websocket, {
            "type": "disconnect",
            "pid": port.pid,
            "tcp_port": port.addr[1],
            "peer_type": port.peer_type,
            "reason": reason,
        })
    
    async def _send_ws_block_load(self, websocket: websockets.ServerConnection | None, port: DayZDebugPort, block_id: int, filenames: list[str]):
        await self._send_or_broadcast(websocket, {
            "type": "block_load",
            "pid": port.pid,
            "tcp_port": port.addr[1],
            "peer_type": port.peer_type,
            "block_id": block_id,
            "filenames": filenames,
        })
    
    async def _send_ws_block_unload(self, websocket: websockets.ServerConnection | None, port: DayZDebugPort, block_id: int, filenames: list[str]):
        await self._send_or_broadcast(websocket, {
            "type": "block_unload",
            "pid": port.pid,
            "tcp_port": port.addr[1],
            "peer_type": port.peer_type,
            "block_id": block_id,
            "filenames": filenames,
        })
    
    async def _send_ws_log(self, websocket: websockets.ServerConnection | None, port: DayZDebugPort, data: str):
        await self._send_or_broadcast(websocket, {
            "type": "log",
            "pid": port.pid,
            "tcp_port": port.addr[1],
            "peer_type": port.peer_type,
            "data": data,
        })
    
    async def _send_ws_output(self, websocket: websockets.ServerConnection | None, data: str):
        await self._send_or_broadcast(websocket, {
            "type": "output",
            "data": data,
        })
    
    async def emit_output(self, data: str):
        await self._send_ws_output(None, data)

    async def _receive_ws(self, websocket: websockets.ServerConnection, type: str, message_json: dict):
        match type:
            case "execCode":
                logging.info(f"got execCode from websocket (tcp_port={message_json.get("tcp_port")})")
                target_port = self.get_one_port(message_json.get("tcp_port"))
                await target_port.exec_code(module=message_json["module"], code=message_json["code"])
            case "recompile":
                filename = message_json["filename"]
                logging.info(f"got recompile from websocket (filename=\"{filename}\", tcp_port={message_json.get("tcp_port")})")
                target_ports = self.get_ports(message_json.get("tcp_port"))
                for target_port in target_ports:
                    block, index = target_port.find_block_and_index_for_filename(filename)
                    await target_port.recompile(block.block_id, index)
            case _:
                raise ValueError(f"unknown message type \"{type}\"")

    async def on_port_connected(self, port: DayZDebugPort):
        tcp_port = port.addr[1]
        if tcp_port in self.ports:
            logging.warning(f"game tcp port {tcp_port} already connected")
        self.ports[tcp_port] = port
    
    async def on_port_disconnected(self, port: DayZDebugPort):
        tcp_port = port.addr[1]
        if tcp_port not in self.ports:
            return

        del self.ports[tcp_port]
        # did not send exit, probably crashed
        await self._send_ws_disconnect(None, port, "crash")

    async def on_port_message(self, port: DayZDebugPort, msg: DZBaseMsg):
        match msg:
            case DZHelloMsg():
                await self._send_ws_connect(None, port)
            case DZExitMsg():
                await self._send_ws_disconnect(None, port, "exit")
                tcp_port = port.addr[1]
                if tcp_port not in self.ports:
                    logging.warning(f"unknown game port {tcp_port} exited")
                    return

                del self.ports[tcp_port]
            case DZBlockLoadMsg():
                await self._send_ws_block_load(None, port, msg.block_id, msg.filenames)
            case DZBlockUnloadMsg():
                await self._send_ws_block_unload(None, port, msg.block_id, msg.filenames)
            case DZLogMsg():
                await self._send_ws_log(None, port, msg.data)

    async def on_websocket_connected(self, websocket: websockets.ServerConnection):
        await self._send_ws_hello(websocket)
        for port in self.ports.values():
            if port.pid != -1:
                # TODO: maybe port needs to be locked to avoid races with game disconnect / code load / code unload notifications from the port
                await self._send_ws_connect(websocket, port)
                for block in port.blocks.values():
                    await self._send_ws_block_load(websocket, port, block.block_id, block.filenames)

    async def on_websocket_disconnected(self, websocket: websockets.ServerConnection):
        print("wsdc")

    async def on_websocket_message(self, websocket: websockets.ServerConnection, message: str):
        try:
            message_json = json.loads(message)
            assert isinstance(message_json["type"], str)
            await self._receive_ws(websocket, message_json["type"], message_json)
        except Exception:
            logging.exception(f"failed to receive websocket message: {message}")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, listener: DayZPortListener, server_port: int, shutdown_evt: asyncio.Event, log_dir: Path | None = None):
    try:
        peer_type = PEERTYPE_SERVER if server_port == 1001 else PEERTYPE_CLIENT  # clients 1000, servers 1001
        buffer = SocketBuffer(reader, writer, log_dir=log_dir)
        protocol = DayZProtocol(buffer)
        port = DayZDebugPort(addr=writer.get_extra_info('peername'), protocol=protocol, peer_type=peer_type)

        peer_type_log = " S" if peer_type == PEERTYPE_SERVER else "C "
        task_prefix.set(f"[PORT:{str(port.addr[1]).ljust(5)} {peer_type_log}]")
        logging.info(f"dayz port connected {port.addr}, parsing hello")

        # receive hello right on connection
        buffer_task = asyncio.create_task(buffer.start())

        msg = await port.recv_one_msg(30)
        assert isinstance(msg, DZHelloMsg)
        assert port.pid != -1

        task_prefix.set(f"[PID:{str(port.pid).ljust(5)} {peer_type_log}]")

        await listener.on_port_connected(port)
        try:
            await listener.on_port_message(port, msg)
            
            port.add_listener(listener)

            logging.info(f"dayz port initialized ({port.addr=}, {port.pid=})")

            done, pending = await asyncio.wait([
                buffer_task,
                asyncio.create_task(port.run()),
                asyncio.create_task(shutdown_evt.wait()),
            ], return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()
            
            for task in done:
                await task
            
        except Exception as e:
            logging.error(f"dayz port exception: ({port.addr=}, {port.pid=})")
        finally:
            logging.info(f"dayz port disconnect {port.addr}")
            await listener.on_port_disconnected(port)
    finally:
        writer.close()


async def mock_client(path="data.bin.txt"):
    logging.info("Running in mock mode using data.bin.txt")

    r, w = await asyncio.open_connection("127.0.0.1", DZDEBUGPORTS[0])

    with open(path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            w.write(chunk)
            await w.drain()
            # await asyncio.sleep(0.005)  # slight delay to simulate packet timing

    w.close()
    await w.wait_closed()
    logging.info("Mock client finished sending data.")


class PromptToolkitHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        print_formatted_text(msg)


class WebSocketBroadcastHandler(logging.Handler):
    def __init__(self, server: DayZDebugWebSocketServer):
        super().__init__()
        self.server = server
        self.queue = asyncio.Queue()
        self._task = asyncio.create_task(self._emit_task())
    
    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.queue.put_nowait(msg)
        except Exception:
            self.handleError(record)
    
    async def _emit_task(self):
        while True:
            msg = await self.queue.get()
            await self.server.emit_output(msg)


class PrefixFilter(logging.Filter):
    def filter(self, record):
        prefix = task_prefix.get()
        if prefix:
            record.msg = f"{prefix} {record.msg}"
        return True
    
def setup_logging(log_prompt: bool, log_file: Path | None, dzws: DayZDebugWebSocketServer | None):
    # Clear existing handlers
    logging.root.handlers.clear()

    level = logging.INFO

    # Console logging (via prompt_toolkit)
    if log_prompt:
        console_handler = PromptToolkitHandler()
        console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        console_handler.setLevel(level)
        logging.root.addHandler(console_handler)
    else:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        stdout_handler.setLevel(level)
        logging.root.addHandler(stdout_handler)

    # File logging
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        file_handler.setLevel(level)
        logging.root.addHandler(file_handler)

    if dzws:
        ws_handler = WebSocketBroadcastHandler(dzws)
        ws_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        ws_handler.setLevel(level)
        logging.root.addHandler(ws_handler)

    # Set global level
    logging.root.setLevel(level)

    logging.root.addFilter(PrefixFilter())


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true", help="Run mock client using data.bin.txt")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--ws", nargs="?", const=WSPORT, type=int, default=None, help=f"Enable WebSocket server. Optional port (default: {WSPORT})")
    parser.add_argument("--log-file", nargs="?", const=LOGFILE, default=None, help=f"Enable log to file. Optional filename (default: {LOGFILE})")
    parser.add_argument("--sniff-dir", nargs="?", const=".", default=None, help=f"Directory to output sniff file. Optional.")
    args = parser.parse_args()

    tasks = []

    if args.ws:
        server = WebSocketServer(host="0.0.0.0", port=args.ws)
        listener = DayZDebugWebSocketServer(server)
        setup_logging(False, log_file=args.log_file, dzws=listener)
        server.add_listener(listener)
        tasks.append(asyncio.create_task(server.run()))
    else:
        setup_logging(True, log_file=args.log_file, dzws=None)
        console = ConsoleInterface()
        listener = DayZDebugConsole(console)
        tasks.append(asyncio.create_task(console.run()))

    shutdown_evt = asyncio.Event()

    servers = []
    for port in DZDEBUGPORTS:
        server = await asyncio.start_server(lambda r, w, _port=port: handle_client(r, w, listener=listener, server_port=_port, shutdown_evt=shutdown_evt, log_dir=args.sniff_dir), "0.0.0.0", port)
        tasks.append(asyncio.create_task(server.serve_forever()))
        servers.append(server)

    if args.mock:
        async def _mock_wrapper():
            await mock_client()
            await asyncio.Future()
        tasks.append(asyncio.create_task(_mock_wrapper()))

    logging.info(f"Listening on ports {DZDEBUGPORTS}")

    async with AsyncExitStack() as stack:
        for server in servers:
            await stack.enter_async_context(server)
        
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            # Propagate any exceptions
            for task in done:
                await task

        except asyncio.CancelledError:
            logging.info("Server shutdown requested via Ctrl+C")
        finally:
            # grace exit
            for task in tasks:
                task.cancel()
            shutdown_evt.set()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user.")