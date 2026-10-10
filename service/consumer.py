from channels.generic.websocket import AsyncWebsocketConsumer
import json


class NIDSConsumer(AsyncWebsocketConsumer):

    async def connect(self):

        self.group_name = "nids_live"

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

        await self.send(
            text_data=json.dumps({
                "type": "connection",
                "message": "NIDS WebSocket Connected"
            })
        )

    async def disconnect(self, close_code):

        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

        print("NIDS WebSocket Disconnected")

    async def nids_message(self, event):

        await self.send(
            text_data=json.dumps(
                event["data"]
            )
        )