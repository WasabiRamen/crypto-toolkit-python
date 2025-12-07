from fastapi import FastAPI
from secrets import token_hex
import asyncio


app = FastAPI()


class PepperDemo:
    def __init__(self, pepper: str):
        self.pepper = pepper

    def add_pepper(self, plain: str) -> str:
        return plain + self.pepper

class PepperGenerator:
    def __init__(self, sec: int = 60):
        self.sec = sec
        self.current_pepper: str | None = None
        self._task: asyncio.Task | None = None

    @staticmethod
    def generate_pepper(length: int = 16) -> str:
        return token_hex(length)

    async def _rotate_loop(self):
        while True:
            self.current_pepper = self.generate_pepper()
            await asyncio.sleep(self.sec)

    async def start(self):
        # 백그라운드 task 생성
        self._task = asyncio.create_task(self._rotate_loop())

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


async def lifespan(app: FastAPI):
    app.state.pepper_generator = PepperGenerator(sec=1)
    await app.state.pepper_generator.start()
    yield
    await app.state.pepper_generator.stop()


pepper_demo = PepperDemo(pepper=app.state.pepper_generator.current_pepper)

def get_pepper_demo() -> PepperDemo:
    return pepper_demo.pepper


@app.get("/pepper")
def get_pepper():
    return pepper_demo.pepper