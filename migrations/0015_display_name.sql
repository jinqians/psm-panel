-- A node's name in clients, as it is (any language, emoji): '' = the flag of
-- its server's country and "<server>-<node>". The panel's own: changing it
-- sends nothing to the server.
ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
