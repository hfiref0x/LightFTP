/*
 * cfgparse.h
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Apr 19, 2017
 *
 *      Author: lightftp
 */

#ifndef CFGPARSE_H_
#define CFGPARSE_H_

char *InitConfig(char *cfg_filename);
int ParseConfig(const char *pcfg, const char *section_name, const char *key_name, char *value, unsigned long value_size_max);

#endif /* CFGPARSE_H_ */
