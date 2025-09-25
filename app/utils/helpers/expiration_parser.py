from datetime import timedelta

def parse_expiration(value: str):
    if value.endswith("m"):
        return timedelta(minutes=int(value[:-1]))
    elif value.endswith("h"):
        return timedelta(hours=int(value[:-1]))
    elif value.endswith("d"):
        return timedelta(days=int(value[:-1]))
    else:
        # Default to minutes if no suffix
        return timedelta(minutes=int(value))