# -*- coding: utf-8 -*-
# © THOORENS Bruno

import base64

from usrv import req, loadJson


def freemobile_sendmsg(title, body, **freemobile):
    freemobile.update(loadJson("freemobile.json"))
    if freemobile != {}:
        freemobile["msg"] = title + ":\n" + body
        return req.POST.sendmsg(
            peer="https://smsapi.free-mobile.fr",
            _jsonify=freemobile
        )


def pushbullet_pushes(title, body, **pushbullet):
    pushbullet.update(loadJson("pushbullet.json"))
    if pushbullet != {}:
        return req.POST.v2.pushes(
            peer="https://api.pushbullet.com",
            _jsonify={"body": body, "title": title, "type": "note"},
            headers={
                'Access-Token': pushbullet.get("token", ""),
            }
        )


def pushover_messages(title, body, **pushover):
    pushover.update(loadJson("pushover.json"))
    if pushover != {}:
        return req.POST(
            "1", "messages.json",
            peer="https://api.pushover.net",
            _urlencode=dict(
                message=body,
                title=title,
                **pushover
            )
        )


def twilio_messages(title, body, **twilio):
    twilio.update(loadJson("twilio.json"))
    if twilio != {}:
        authentication = base64.b64encode(
            ("%s:%s" % (twilio["sid"], twilio["auth"])).encode('utf-8')
        )
        return req.POST(
            "2010-04-01", "Accounts", twilio["sid"], "Messages.json",
            peer="https://api.twilio.com",
            _urlencode={
                "From": twilio["sender"],
                "To": twilio["receiver"],
                "Body": body,
            },
            headers={
                "Authorization": "Basic %s" % authentication.decode('ascii')
            }
        )


def send(title, body, data_folder=None):
    title = title.decode("utf-8") if isinstance(title, bytes) else title
    body = body.decode("utf-8") if isinstance(body, bytes) else body

    for func in [
        freemobile_sendmsg,
        pushbullet_pushes,
        pushover_messages,
        twilio_messages
    ]:
        response = func(
            title, body,
            **loadJson(f"{func.__name__.split('_')[0]}.notify", data_folder)
        )
        if isinstance(response, dict):
            if response.get("status", 1000) < 300:
                return response
