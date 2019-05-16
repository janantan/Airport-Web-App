import os
import datetime
import jdatetime
import utils, config, equipments

amhs_cursor = utils.config_mongodb(utils.MONGO_HOST, utils.MONGO_PORT, utils.AMHS_DB_NAME)

for i in range(1, amhs_cursor.records.estimated_document_count()+1):

	record = amhs_cursor.records.find_one({"id": i})
	#channels_status = record['channels_status']
	#for channel in ['tis', 'scr']:
		#channels_status[channel] = {
    	#'during':"",
    	#'from':"",
    	#'to':"",
    	#'reason':"",
    	#'end':""
    	#}
    
	#if record['shift'] == 'D':
		#n_d = 'Day'
	#elif record['shift'] == 'N':
		#n_d = 'Night'

	amhs_cursor.records.update_many(
        {"id": i},
        {'$set': {
        'id': i,
        'shift': n_d
        }
        }
        )