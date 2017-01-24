# -*- coding: utf-8 -*-


from .op import Op


def exec_(plg, db, ops_valid, perms):
    plg.update_db(db)

    plg.update_ops_valid(ops_valid)

    plg.update_perms(perms)
