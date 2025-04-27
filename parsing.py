import time
# from model.model_pipeline import process          # the function you already wrote
from capture import process          # the function you already wrote
from app import create_app            # only needed if process() touches Flask / DB
import asyncio

# Feel free to tweak the defaults
PARSE_IP      = "192.168.0.122"       
PARSE_PERIOD  = 5                     # seconds between successive calls (not used)

def run_parser(ip=PARSE_IP, period=PARSE_PERIOD):
    """
    Continuously invoke pipeline.process(ip) every <period> seconds.
    If process() needs Flask's application / database context, we wrap it.
    """
    app = create_app()
    with app.app_context(): 
        # while True:   # for auto-restart
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                process()
                print('stopped')
            except Exception as e:
                # Never let an uncaught exception kill the daemon thread
                print(f"[parser] error while processing {ip}: {e!s}")
