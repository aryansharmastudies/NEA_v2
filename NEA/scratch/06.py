


if metadata['is_dir'] and event_type == 'created':
    CreateDir(metadata, self.address).apply()
elif not metadata['is_dir'] and event_type == 'created':
    CreateFile(metadata, self.address, self.connection).apply()
elif event_type == 'deleted':
    Delete(metadata, self.address).apply()
elif event_type == 'moved':
    Move(metadata, self.address).apply()
elif not metadata['is_dir'] and event_type == 'modified':
    Modify(metadata, self.address, self.connection).apply()