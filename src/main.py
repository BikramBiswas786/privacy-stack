const Apify = require('apify');
const cheerio = require('cheerio');
const axios = require('axios');

Apify.main(async () => {
    const dataset = await Apify.openDataset();
    const requestQueue = await Apify.openRequestQueue();
    
    // 🔍 PRIVACY KEYWORDS - Your targets
    const privacyKeywords = [
        'online privacy',
        'financial privacy', 
        'crypto privacy',
        'privacy mixnets',
        'anonymity networks',
        'privacy-preserving',
        'zero knowledge privacy',
        'differential privacy',
        'nym mixnet',
        'tor privacy'
    ];
    
    // 🚀 arXiv privacy papers (REAL data source)
    const privacySources = [
        'https://arxiv.org/search/?query=online+privacy&searchtype=all&source=header',
        'https://arxiv.org/search/?query=financial+privacy&searchtype=all&source=header', 
        'https://arxiv.org/search/?query=crypto+privacy&searchtype=all&source=header',
        'https://arxiv.org/search/?query=mixnet&searchtype=all&source=header',
        'https://arxiv.org/search/?query=anonymity+network&searchtype=all&source=header'
    ];
    
    // Add sources to queue
    for (const url of privacySources) {
        await requestQueue.addRequest({ url });
    }
    
    // 🕷️ Scrape arXiv results
    const crawler = new Apify.PuppeteerCrawler({
        requestQueue,
        handlePageFunction: async ({ page, request }) => {
            console.log(`📄 Scraping: ${request.url}`);
            
            // Extract paper titles, authors, PDFs from arXiv
            const papers = await page.evaluate(() => {
                const results = [];
                document.querySelectorAll('.arxiv-result').forEach(item => {
                    const titleEl = item.querySelector('.title a');
                    const authorsEl = item.querySelector('.authors');
                    const pdfEl = item.querySelector('.pdf-link');
                    
                    if (titleEl) {
                        results.push({
                            title: titleEl.textContent.trim(),
                            authors: authorsEl ? authorsEl.textContent.trim() : 'N/A',
                            pdf: pdfEl ? pdfEl.href : 'N/A',
                            url: titleEl.href,
                            source: 'arXiv.org',
                            keywords: window.location.search.slice(1)
                        });
                    }
                });
                return results.slice(0, 10); // Top 10 per page
            });
            
            // Push to dataset
            if (papers.length > 0) {
                await dataset.pushData(papers);
                console.log(`✅ Pushed ${papers.length} privacy papers from ${request.url}`);
            }
        },
        
        maxRequestsPerCrawl: 10,
        maxConcurrency: 3
    });
    
    await crawler.run();
    
    // 🎯 Final stats
    const datasetStats = await dataset.getInfo();
    console.log(`\n🎉 PRIVACY STACK COMPLETE!`);
    console.log(`📊 Total papers: ${datasetStats.itemCount}`);
    console.log(`🔗 View dataset: https://console.apify.com/storage/datasets/${datasetStats.id}`);
});

