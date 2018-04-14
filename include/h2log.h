#ifndef __H2LOG_H__

#define __H2LOG_H__

#include "esp_log.h"

#define ERROR	E
#define WARNING	W
#define INFO	I
#define DEBUG	D

#define CONCAT(a, b)	a##b

#define log(level, tag, ...) CONCAT(ESP_LOG, level)(tag, ##__VA_ARGS__)

#endif /* end of include guard: __H2LOG_H__ */
