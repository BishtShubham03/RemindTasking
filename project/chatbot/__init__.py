import inspect
from chat import reminders

actions = {}
actions.update(dict(inspect.getmembers(reminders, inspect.isfunction)))
