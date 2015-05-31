loginbp
=======

This is a flask blueprint that can be registered onto an app to quickly add a
login feature.

You must add a users_api to the Flask app, which implements ``get_id`` and
``login`` methods.
