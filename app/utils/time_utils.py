from datetime import datetime, timezone
from zoneinfo import ZoneInfo


IST_ZONE = ZoneInfo("Asia/Kolkata")


def utc_to_ist(utc_time):
    """Convert UTC datetime to IST (UTC+5:30)."""
    if not utc_time:
        return None
    if utc_time.tzinfo is None:
        utc_time = utc_time.replace(tzinfo=timezone.utc)
    return utc_time.astimezone(IST_ZONE)


def _choose_ist_naive(timestamp):
    """Choose IST interpretation for naive datetime values."""
    now_ist = datetime.now(IST_ZONE).replace(tzinfo=None)
    assumed_ist = timestamp
    assumed_utc = timestamp.replace(tzinfo=timezone.utc).astimezone(IST_ZONE).replace(tzinfo=None)
    if abs((assumed_ist - now_ist).total_seconds()) <= abs((assumed_utc - now_ist).total_seconds()):
        return assumed_ist
    return assumed_utc


def _format_ist(dt_value, include_date=True):
    if include_date:
        return f"{dt_value.strftime('%d-%b-%Y %H:%M:%S')} IST"
    return f"{dt_value.strftime('%H:%M:%S')} IST"


def format_timestamp_to_ist(value, include_date=True, assume_tz="auto"):
    """Format a timestamp (datetime, epoch, or string) into IST for display."""
    if value is None:
        return ""

    if isinstance(value, datetime):
        if value.tzinfo:
            return _format_ist(value.astimezone(IST_ZONE), include_date)
        if assume_tz == "ist":
            return _format_ist(value, include_date)
        if assume_tz == "utc":
            return _format_ist(value.replace(tzinfo=timezone.utc).astimezone(IST_ZONE), include_date)
        return _format_ist(_choose_ist_naive(value), include_date)

    if isinstance(value, (int, float)):
        dt_value = datetime.fromtimestamp(value, tz=timezone.utc).astimezone(IST_ZONE)
        return _format_ist(dt_value, include_date)

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        if "IST" in text:
            return text

        iso_text = text.replace("Z", "+00:00")
        try:
            dt_value = datetime.fromisoformat(iso_text)
            if dt_value.tzinfo:
                return _format_ist(dt_value.astimezone(IST_ZONE), include_date)
            if assume_tz == "ist":
                return _format_ist(dt_value, include_date)
            if assume_tz == "utc":
                return _format_ist(dt_value.replace(tzinfo=timezone.utc).astimezone(IST_ZONE), include_date)
            return _format_ist(_choose_ist_naive(dt_value), include_date)
        except ValueError:
            pass

        for fmt in ("%d-%b-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
            try:
                dt_value = datetime.strptime(text, fmt)
                if assume_tz == "ist":
                    return _format_ist(dt_value, include_date)
                if assume_tz == "utc":
                    return _format_ist(dt_value.replace(tzinfo=timezone.utc).astimezone(IST_ZONE), include_date)
                return _format_ist(_choose_ist_naive(dt_value), include_date)
            except ValueError:
                continue

        return text

    return str(value)


def format_trade_timestamp(timestamp):
    """Format trade timestamp as IST.

    All entry_time/exit_time values are stored via datetime.utcnow() (naive UTC).
    Using assume_tz='utc' ensures consistent conversion regardless of when the
    data is viewed. The previous 'auto' mode used a heuristic that could flip
    after market hours, showing raw UTC values as IST.
    """
    return format_timestamp_to_ist(timestamp, include_date=True, assume_tz="utc")
