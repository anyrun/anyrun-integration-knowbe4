from dotenv import load_dotenv

load_dotenv()

from anyrun_connector import ANYRUN
from phisher import Phisher

if __name__ == "__main__":
    message_id = "82ec475f-0096-46b8-986d-3f9c12fb0af3"

    with Phisher() as phisher:
        # message = phisher.get_message(message_id=message_id)

        messages, pagination = phisher.list_messages(page=1)

        message = messages[0]

    ar = ANYRUN()

    task_id = ar.submit_download_windows(message.raw_url)

    print(task_id)
