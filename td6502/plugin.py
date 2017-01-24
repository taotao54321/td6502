# -*- coding: utf-8 -*-


import os.path
import importlib.util
from importlib.machinery import SourceFileLoader


# 同梱プラグインの相対パッケージ名
_PLUGIN_PACKAGE = "plugins"


class PluginLoadError(Exception): pass

class Plugin:
    def __init__(self, identifier, args, org, size):
        # identifier はパス名もしくは同梱プラグイン名
        # まずパス名と仮定してロードを試みる
        module = Plugin._load_by_path(identifier)

        # パス名でのロードが失敗した場合、同梱プラグインのロードを試みる
        if module is None:
            module = Plugin._load_by_name(identifier)

        if module is None: raise PluginLoadError("cannot load {}".format(identifier))

        self.instance= module.create(org, size, args)

    def exec_(self, db, ops_valid, perms):
        self.instance.update_db(db)

        self.instance.update_ops_valid(ops_valid)

        self.instance.update_perms(perms)

    # importlib の使い方はイマイチ自信なし。一応動いてるっぽいけど

    @staticmethod
    def _load_by_path(path):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            return SourceFileLoader(name, path).load_module()
        except Exception:
            return None

    @staticmethod
    def _load_by_name(name):
        relative = "..{}.{}".format(_PLUGIN_PACKAGE, name)
        spec = importlib.util.find_spec(relative, __name__)
        if not spec: return None
        try:
            return spec.loader.load_module()
        except Exception:
            return None
