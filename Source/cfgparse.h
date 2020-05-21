/*
* cfgparse.h
*
*  Created on: Aug 20, 2016
*
*  Modified on: May 15, 2020
*
*      Author: lightftp
*/

#ifndef CFGPARSE_H_
#define CFGPARSE_H_

char *config_init(char *cfg_filename);
int config_parse(const char *pcfg, const char *section_name, const char *key_name, char *value, unsigned long value_size_max);

#endif /* CFGPARSE_H_ */
