from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import check_health, http_ops
logger = get_logger('http')

class HTTP(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation:[{}]'.format(operation))
        operation = http_ops.get(operation, None)
        if not operation:
            logger.info('Unsupported operation [{}]'.format(operation))
            raise ConnectorError('Unsupported operation')
        result = operation(config, params)
        return result

    def check_health(self, config):
        return check_health(config)
