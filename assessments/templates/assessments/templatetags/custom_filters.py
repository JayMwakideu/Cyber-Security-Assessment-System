from django import template

register = template.Library()

@register.filter
def replace(value, arg):
    """
    Replace all occurrences of the given argument in the value with an empty string.
    arg should be a single string to replace.
    """
    if not isinstance(arg, str) or not arg:
        return value
    return value.replace(arg, '')

@register.filter
def get_item(dictionary, key):
    """
    Get an item from a dictionary using a key.
    """
    return dictionary.get(key)