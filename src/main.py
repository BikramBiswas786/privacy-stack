const Apify = require('apify');
const axios = require('axios');
const cheerio = require('cheerio');

Apify.main(async () => {
    const input = await Apify.getInput();
    
    console.log('Input:', JSON.stringify(input, null, 2));

    const {
        sources = [],
        maxPapersPerSource = 50,
        includeImplementations = true,
        extractAbstracts = true,
        timeout = 30
    } = input;

    const requestList = await Apify.openRequestList('URLS', 
        sources.map(source => ({
            url: source.url,
            userData: {
                category: source.category,
                sourceName: source.name
            }
        }))
    );

    const dataset = await Apify.openDataset();
    const projects = {};
    let projectCount = 0;

    const crawler = new Apify.CheerioCrawler({
        requestList,
        maxRequestsPerCrawl: sources.length * maxPapersPerSource,
        handlePageTimeoutSecs: timeout,

        handlePageFunction: async ({ request, body }) => {
            console.log(`Processing: ${request.url}`);

            try {
                const $ = cheerio.load(body);
                const { category, sourceName } = request.userData;

                const papers = extractPapersFromPage($, category, sourceName);

                for (const paper of papers) {
                    if (projectCount >= maxPapersPerSource) break;

                    const projectKey = `project_${projectCount + 1}`;
                    
                    let implementation = null;
                    if (includeImplementations && paper.githubUrl) {
                        implementation = await fetchGithubImplementation(paper.githubUrl, timeout);
                    }

                    projects[projectKey] = {
                        title: paper.title,
                        category: category,
                        template: 'research-paper',
                        authors: paper.authors || [],
                        year: paper.year || new Date().getFullYear(),
                        abstract: paper.abstract || 'Abstract not available',
                        arxivId: paper.arxivId || null,
                        doi: paper.doi || null,
                        url: paper.url,
                        pythonImplementation: implementation ? {
                            available: true,
                            repositoryUrl: paper.githubUrl,
                            repositoryName: extractRepoName(paper.githubUrl),
                            language: 'python',
                            dependencies: implementation.dependencies || [],
                            maintainedBy: implementation.maintainer || 'Unknown',
                            stars: implementation.stars || 0
                        } : {
                            available: false,
                            repositoryUrl: null,
                            repositoryName: null,
                            language: null,
                            dependencies: [],
                            maintainedBy: null,
                            stars: 0
                        },
                        keyTopics: paper.topics || [],
                        relatedWorks: paper.relatedWorks || [],
                        sourceUrl: request.url,
                        scrapedAt: new Date().toISOString(),
                        qualityScore: calculateQualityScore(paper),
                        notes: paper.notes || null
                    };

                    projectCount++;
                    console.log(`Added project ${projectCount}: ${paper.title}`);
                }

            } catch (error) {
                console.error(`Error processing ${request.url}:`, error.message);
            }
        },

        handleFailedRequestFunction: async ({ request, error }) => {
            console.error(`Failed to process ${request.url}: ${error.message}`);
        }
    });

    await crawler.run();

    const output = {
        projects,
        metadata: {
            totalProjects: projectCount,
            projectsWithImplementation: Object.values(projects).filter(p => p.pythonImplementation.available).length,
            categories: calculateCategoryStats(projects),
            scrapingStartTime: new Date(Date.now() - 60000).toISOString(),
            scrapingEndTime: new Date().toISOString(),
            sourcesCovered: sources.map(s => s.name)
        }
    };

    console.log('Final Output:', JSON.stringify(output, null, 2));
    await dataset.pushData(output);
    console.log(`✅ Successfully scraped ${projectCount} research papers`);
});

function extractPapersFromPage($, category, sourceName) {
    const papers = [];
    
    // arXiv specific selectors
    $('article, .paper, .result, li.list-title, .js-title-link').each((index, element) => {
        const $elem = $(element);
        const title = $elem.find('h2, h3, .title, a[title]').first().text().trim();
        
        if (title && title.length > 10) {
            const paper = {
                title: title,
                authors: extractAuthors($elem),
                abstract: extractAbstracts ? $elem.find('.abstract, .summary').text().trim().substring(0, 500) : '',
                url: $elem.find('a[href*="arxiv"], a[href*="doi"], a').first().attr('href') || '',
                githubUrl: $elem.find('a[href*="github.com"]').attr('href') || null,
                year: extractYear($elem.text()),
                topics: extractTopics($elem),
                relatedWorks: [],
                notes: `Extracted from ${sourceName}`
            };
            
            // Make URL absolute
            if (paper.url && !paper.url.startsWith('http')) {
                paper.url = new URL(paper.url, 'https://arxiv.org').href;
            }
            
            papers.push(paper);
        }
    });
    
    return papers.slice(0, 10); // Limit per page
}

function extractAuthors($elem) {
    const authorText = $elem.find('.authors, [class*="author"], .list-authors').text();
    if (!authorText) return [];
    
    return authorText
        .split(/[,;]/)
        .map(author => author.trim())
        .filter(author => author.length > 2)
        .slice(0, 10);
}

function extractYear(text) {
    const match = text.match(/\b(19|20)\d{2}\b/);
    return match ? parseInt(match[0]) : new Date().getFullYear();
}

function extractTopics($elem) {
    const topicsText = $elem.find('[class*="keyword"], [class*="tag"], .tags').text();
    if (!topicsText) return [];
    
    return topicsText
        .split(/[,;]/)
        .map(topic => topic.trim())
        .filter(topic => topic.length > 0)
        .slice(0, 10);
}

function extractRepoName(githubUrl) {
    if (!githubUrl) return null;
    const match = githubUrl.match(/github\.com\/([^\/]+)\/([^\/]+?)(?:\/|$)/);
    return match ? `${match[1]}/${match[2]}` : null;
}

async function fetchGithubImplementation(githubUrl, timeout) {
    try {
        const apiUrl = githubUrl
            .replace('https://github.com/', 'https://api.github.com/repos/')
            .replace(/\/$/, '');

        const response = await axios.get(apiUrl, {
            timeout: timeout * 1000,
            headers: {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'PrivacyStack-Scraper/1.0'
            }
        });

        const repo = response.data;
        let dependencies = [];
        
        try {
            const reqResponse = await axios.get(`${apiUrl}/contents/requirements.txt`, {
                timeout: timeout * 1000,
                headers: {
                    'Accept': 'application/vnd.github.v3.raw',
                    'User-Agent': 'PrivacyStack-Scraper/1.0'
                }
            });
            dependencies = reqResponse.data
                .split('\n')
                .filter(line => line.trim() && !line.startsWith('#'))
                .map(line => line.split('==')[0].trim())
                .slice(0, 10);
        } catch (e) {
            console.log('No requirements.txt found');
        }

        return {
            maintainer: repo.owner?.login || 'Unknown',
            stars: repo.stargazers_count || 0,
            dependencies: dependencies
        };

    } catch (error) {
        console.warn(`Could not fetch GitHub repo ${githubUrl}: ${error.message}`);
        return null;
    }
}

function calculateQualityScore(paper) {
    let score = 0.5;
    if (paper.abstract && paper.abstract.length > 100) score += 0.2;
    if (paper.authors && paper.authors.length > 0) score += 0.15;
    if (paper.year && paper.year > 2018) score += 0.15;
    return Math.min(score, 1.0);
}

function calculateCategoryStats(projects) {
    const stats = {};
    Object.values(projects).forEach(project => {
        const category = project.category || 'other';
        stats[category] = (stats[category] || 0) + 1;
    });
    return stats;
}
