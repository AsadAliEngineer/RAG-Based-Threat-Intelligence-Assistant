# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CwecrawlerItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    cwe_id = scrapy.Field()
    cwe_canfollow = scrapy.Field()
    pass
