from __future__ import print_function

import codecs
from collections import OrderedDict
import fnmatch
from io import StringIO, BytesIO
import logging
import os
import uuid

from ruamel.yaml import RoundTripConstructor, RoundTripRepresenter, YAML, YAMLError

from esphomeyaml import core
from esphomeyaml.core import EsphomeyamlError, HexInt, IPAddress, Lambda, MACAddress, TimePeriod
from esphomeyaml.py_compat import text_type

_LOGGER = logging.getLogger(__name__)

# Mostly copied from Home Assistant because that code works fine and
# let's not reinvent the wheel here

SECRET_YAML = u'secrets.yaml'


class NodeListClass(list):
    """Wrapper class to be able to add attributes on a list."""


class ExtRoundTripConstructor(RoundTripConstructor):
    """Extended RoundTripConstructor."""


class ExtRoundTripRepresenter(RoundTripRepresenter):
    """Extended RoundTripRepresenter"""

    def represent_omap(self, tag, omap, flow_style=None):
        if tag == u'tag:yaml.org,2002:omap':
            return RoundTripRepresenter.represent_mapping(self, u'tag:yaml.org,2002:map',
                                                          omap, flow_style)
        return RoundTripRepresenter.represent_omap(self, tag, omap, flow_style)


def load_yaml(fname):
    """Load a YAML file."""
    if not hasattr(ExtRoundTripConstructor, 'name'):
        ExtRoundTripConstructor.name = fname
    yaml = YAML(typ='rt')
    yaml.Constructor = ExtRoundTripConstructor

    try:
        with codecs.open(fname, encoding='utf-8') as conf_file:
            return yaml.load(conf_file) or OrderedDict()
    except YAMLError as exc:
        raise EsphomeyamlError(exc)
    except IOError as exc:
        raise EsphomeyamlError(u"Error accessing file {}: {}".format(fname, exc))
    except UnicodeDecodeError as exc:
        _LOGGER.error(u"Unable to read file %s: %s", fname, exc)
        raise EsphomeyamlError(exc)


def dump(dict_):
    """Dump YAML to a string and remove null."""
    yaml = YAML(typ='rt')
    yaml.Representer = ExtRoundTripRepresenter
    stream = BytesIO()
    yaml.dump(dict_, stream)
    return stream.getvalue()


def _env_var_yaml(_, node):
    var = node.value
    if var not in os.environ:
        raise EsphomeyamlError(u"Environment variable {} not defined.".format(var))
    return os.environ[var]


def _include_yaml(constructor, node):
    fname = os.path.join(os.path.dirname(constructor.name), node.value)
    return load_yaml(fname)


def _is_file_valid(name):
    """Decide if a file is valid."""
    return not name.startswith(u'.')


def _find_files(directory, pattern):
    """Recursively load files in a directory."""
    for root, dirs, files in os.walk(directory, topdown=True):
        dirs[:] = [d for d in dirs if _is_file_valid(d)]
        for basename in files:
            if _is_file_valid(basename) and fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def _include_dir_named_yaml(constructor, node):
    mapping = OrderedDict()  # type: OrderedDict
    loc = os.path.join(os.path.dirname(constructor.name), node.value)
    for fname in _find_files(loc, '*.yaml'):
        filename = os.path.splitext(os.path.basename(fname))[0]
        mapping[filename] = load_yaml(fname)
    return mapping


def _include_dir_merge_named_yaml(constructor, node):
    mapping = OrderedDict()  # type: OrderedDict
    loc = os.path.join(os.path.dirname(constructor.name), node.value)
    for fname in _find_files(loc, '*.yaml'):
        if os.path.basename(fname) == SECRET_YAML:
            continue
        loaded_yaml = load_yaml(fname)
        if isinstance(loaded_yaml, dict):
            mapping.update(loaded_yaml)
    return mapping


def _include_dir_list_yaml(constructor, node):
    loc = os.path.join(os.path.dirname(constructor.name), node.value)
    return [load_yaml(f) for f in _find_files(loc, '*.yaml')
            if os.path.basename(f) != SECRET_YAML]


def _include_dir_merge_list_yaml(constructor, node):
    path = os.path.join(os.path.dirname(constructor.name), node.value)
    merged_list = []
    for fname in _find_files(path, '*.yaml'):
        if os.path.basename(fname) == SECRET_YAML:
            continue
        loaded_yaml = load_yaml(fname)
        if isinstance(loaded_yaml, list):
            merged_list.extend(loaded_yaml)
    return merged_list


# pylint: disable=protected-access
def _secret_yaml(constructor, node):
    secret_path = os.path.join(os.path.dirname(constructor.name), SECRET_YAML)
    secrets = load_yaml(secret_path)
    if node.value not in secrets:
        raise EsphomeyamlError(u"Secret {} not defined".format(node.value))
    return secrets[node.value]


def _lambda(constructor, node):
    return Lambda(text_type(node.value))


ExtRoundTripConstructor.add_constructor('!env_var', _env_var_yaml)
ExtRoundTripConstructor.add_constructor('!secret', _secret_yaml)
ExtRoundTripConstructor.add_constructor('!include', _include_yaml)
ExtRoundTripConstructor.add_constructor('!include_dir_list', _include_dir_list_yaml)
ExtRoundTripConstructor.add_constructor('!include_dir_merge_list',
                                        _include_dir_merge_list_yaml)
ExtRoundTripConstructor.add_constructor('!include_dir_named', _include_dir_named_yaml)
ExtRoundTripConstructor.add_constructor('!include_dir_merge_named',
                                        _include_dir_merge_named_yaml)
ExtRoundTripConstructor.add_constructor('!lambda', _lambda)


def stringify_representer(representer, data):
    return representer.represent_str(str(data))


TIME_PERIOD_UNIT_MAP = {
    'microseconds': 'us',
    'milliseconds': 'ms',
    'seconds': 's',
    'minutes': 'min',
    'hours': 'h',
    'days': 'd',
}


def represent_time_period(representer, data):
    dictionary = data.as_dict()
    if len(dictionary) == 1:
        unit, value = dictionary.popitem()
        out = '{}{}'.format(value, TIME_PERIOD_UNIT_MAP[unit])
        return stringify_representer(representer, out)
    return representer.represent_dict(dictionary)


def represent_lambda(representer, data):
    return representer.represent_scalar(tag='!lambda', value=data.value, style='|')


def represent_id(representer, data):
    return stringify_representer(representer, data.id)


ExtRoundTripRepresenter.add_representer(HexInt, stringify_representer)
ExtRoundTripRepresenter.add_representer(IPAddress, stringify_representer)
ExtRoundTripRepresenter.add_representer(MACAddress, stringify_representer)
ExtRoundTripRepresenter.add_multi_representer(TimePeriod, represent_time_period)
ExtRoundTripRepresenter.add_multi_representer(Lambda, represent_lambda)
ExtRoundTripRepresenter.add_multi_representer(core.ID, represent_id)
ExtRoundTripRepresenter.add_multi_representer(uuid.UUID, stringify_representer)
