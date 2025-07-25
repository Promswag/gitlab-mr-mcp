import express from 'express';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { Gitlab } from '@gitbeaker/rest';
import { authenticateJWT } from './authMiddleware.js';
import { z } from 'zod';

const GITLAB_TOKEN = process.env.REMOTE_GITLAB_MCP_GITLAB_TOKEN;
if (!GITLAB_TOKEN) {
  console.error(
    'Error: REMOTE_GITLAB_MCP_GITLAB_TOKEN environment variable is not set.'
  );
}
const GITLAB_HOST =
  process.env.REMOTE_GITLAB_MCP_GITLAB_HOSTNAME || 'https://gitlab.com';

const api = new Gitlab({
  host: GITLAB_HOST,
  token: GITLAB_TOKEN,
});

const app = express();
app.use(express.json(), authenticateJWT);

const wrapper = express();

wrapper.get('/gitlab/ping', async(req, res) => {
  res.send("pong")
})
wrapper.use('/gitlab', app)
wrapper.use((req, res) => {
  res.status(404).send('Nothing to see here...');
});

// Map to store transports by session ID
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

// Helper function to format errors for MCP responses
const formatErrorResponse = (error: Error): any => ({
  content: [
    {
      type: 'text',
      text: `Error: ${error.message}}`,
    },
  ],
  isError: true,
});

// Handle POST requests for client-to-server communication
app.post('/', async (req, res) => {
  // Check for existing session ID
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports[sessionId]) {
    // Reuse existing transport
    transport = transports[sessionId];
  } else if (!sessionId && isInitializeRequest(req.body)) {
    // New initialization request
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        // Store the transport by session ID
        transports[sessionId] = transport;
      },
    });

    // Clean up transport when closed
    transport.onclose = () => {
      if (transport.sessionId) {
        delete transports[transport.sessionId];
      }
    };
    const server = new McpServer({
      name: 'example-server',
      version: '1.0.0',
    });

    server.tool(
      'get_projects',
      'Get a list of projects with id, name, description, web_url and other useful information.',
      {
        verbose: z
          .boolean()
          .default(false)
          .describe(
            'By default a filtered version is returned, suitable for most cases. Only set true if more information is needed.'
          ),
      },
      async ({ verbose }) => {
        try {
          const projectFilter = {
            ...(process.env.MR_MCP_MIN_ACCESS_LEVEL
              ? {
                minAccessLevel: parseInt(
                  process.env.MR_MCP_MIN_ACCESS_LEVEL,
                  10
                ),
              }
              : {}),
            ...(process.env.MR_MCP_PROJECT_SEARCH_TERM
              ? { search: process.env.MR_MCP_PROJECT_SEARCH_TERM }
              : {}),
          };
          const projects = await api.Projects.all({
            membership: true,
            ...projectFilter,
          });
          const filteredProjects = verbose
            ? projects
            : projects.map((project) => ({
              id: project.id,
              description: project.description,
              name: project.name,
              path: project.path,
              path_with_namespace: project.path_with_namespace,
              web_url: project.web_url,
              default_branch: project.default_branch,
            }));

          const projectsText =
            Array.isArray(filteredProjects) && filteredProjects.length > 0
              ? JSON.stringify(filteredProjects, null, 2)
              : 'No projects found.';
          return {
            content: [{ type: 'text', text: projectsText }],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'list_open_merge_requests',
      'Lists all open merge requests in the project',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        verbose: z
          .boolean()
          .default(false)
          .describe(
            'By default a filtered version is returned, suitable for most cases. Only set true if more information is needed.'
          ),
      },
      async ({ verbose, project_id }) => {
        try {
          const mergeRequests = await api.MergeRequests.all({
            projectId: project_id,
            state: 'opened',
          });

          const filteredMergeRequests = verbose
            ? mergeRequests
            : mergeRequests.map((mr) => ({
              iid: mr.iid,
              project_id: mr.project_id,
              title: mr.title,
              description: mr.description,
              state: mr.state,
              web_url: mr.web_url,
            }));
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(filteredMergeRequests, null, 2),
              },
            ],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'get_merge_request_details',
      'Get details about a specific merge request of a project like title, source-branch, target-branch, web_url, ...',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        verbose: z
          .boolean()
          .default(false)
          .describe(
            'By default a filtered version is returned, suitable for most cases. Only set true if more information is needed.'
          ),
      },
      async ({ project_id, merge_request_iid, verbose }) => {
        try {
          const mr = await api.MergeRequests.show(
            project_id,
            merge_request_iid
          );
          const filteredMr = verbose
            ? mr
            : {
              title: mr.title,
              description: mr.description,
              state: mr.state,
              web_url: mr.web_url,
              target_branch: mr.target_branch,
              source_branch: mr.source_branch,
              merge_status: mr.merge_status,
              detailed_merge_status: mr.detailed_merge_status,
              diff_refs: mr.diff_refs,
            };
          return {
            content: [
              { type: 'text', text: JSON.stringify(filteredMr, null, 2) },
            ],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'get_merge_request_comments',
      'Get general and file diff comments of a certain merge request',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        verbose: z
          .boolean()
          .default(false)
          .describe(
            'By default a filtered version is returned, suitable for most cases. Only set true if more information is needed.'
          ),
      },
      async ({ project_id, merge_request_iid, verbose }) => {
        try {
          const discussions = await api.MergeRequestDiscussions.all(
            project_id,
            merge_request_iid
          );

          if (verbose) {
            return {
              content: [
                { type: 'text', text: JSON.stringify(discussions, null, 2) },
              ],
            };
          }

          const unresolvedNotes = discussions
            .flatMap((note) => note.notes ?? [])
            .filter((note) => note.resolved === false);
          const disscussionNotes = unresolvedNotes
            .filter((note) => note.type === 'DiscussionNote')
            .map((note) => ({
              id: note.id,
              noteable_id: note.noteable_id,
              body: note.body,
              author_name: note.author.name,
            }));
          const diffNotes = unresolvedNotes
            .filter((note) => note.type === 'DiffNote')
            .map((note) => ({
              id: note.id,
              noteable_id: note.noteable_id,
              body: note.body,
              author_name: note.author.name,
              position: note.position,
            }));
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    disscussionNotes,
                    diffNotes,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'add_merge_request_comment',
      'Add a general comment to a merge request',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        comment: z.string().describe('The comment text'),
      },
      async ({ project_id, merge_request_iid, comment }) => {
        try {
          const note = await api.MergeRequestDiscussions.create(
            project_id,
            merge_request_iid,
            comment
          );
          return {
            content: [{ type: 'text', text: JSON.stringify(note, null, 2) }],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'add_merge_request_diff_comment',
      'Add a comment of a merge request at a specific line in a file diff',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        comment: z.string().describe('The comment text'),
        base_sha: z.string().describe('The SHA of the base commit'),
        start_sha: z.string().describe('The SHA of the start commit'),
        head_sha: z.string().describe('The SHA of the head commit'),
        file_path: z
          .string()
          .describe('The path to the file being commented on'),
        line_number: z
          .string()
          .describe('The line number in the new version of the file'),
      },
      async ({
        project_id,
        merge_request_iid,
        comment,
        base_sha,
        start_sha,
        head_sha,
        file_path,
        line_number,
      }) => {
        try {
          const discussion = await api.MergeRequestDiscussions.create(
            project_id,
            merge_request_iid,
            comment,
            {
              position: {
                baseSha: base_sha,
                startSha: start_sha,
                headSha: head_sha,
                oldPath: file_path,
                newPath: file_path,
                positionType: 'text',
                newLine: line_number,
              },
            }
          );
          return {
            content: [
              { type: 'text', text: JSON.stringify(discussion, null, 2) },
            ],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'get_merge_request_diff',
      'Get the file diffs of a certain merge request',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
      },
      async ({ project_id, merge_request_iid }) => {
        try {
          const diff = await api.MergeRequests.allDiffs(
            project_id,
            merge_request_iid
          );
          const diffText =
            Array.isArray(diff) && diff.length > 0
              ? JSON.stringify(diff, null, 2)
              : 'No diff data available for this merge request.';
          return {
            content: [{ type: 'text', text: diffText }],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'get_issue_details',
      'Get details of an issue within a certain project',
      {
        project_id: z.number().describe('The project ID of the issue'),
        issue_iid: z
          .number()
          .describe('The internal ID of the issue within the project'),
        verbose: z
          .boolean()
          .default(false)
          .describe(
            'By default a filtered version is returned, suitable for most cases. Only set true if more information is needed.'
          ),
      },
      async ({ project_id, issue_iid, verbose }) => {
        try {
          const issue = await api.Issues.show(issue_iid, {
            projectId: project_id,
          });

          const filteredIssue = verbose
            ? issue
            : {
              title: issue.title,
              description: issue.description,
            };

          return {
            content: [
              { type: 'text', text: JSON.stringify(filteredIssue, null, 2) },
            ],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'set_merge_request_description',
      'Set the description of a merge request',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        description: z.string().describe('The description text'),
      },
      async ({ project_id, merge_request_iid, description }) => {
        try {
          const mr = await api.MergeRequests.edit(
            project_id,
            merge_request_iid,
            { description }
          );
          return {
            content: [{ type: 'text', text: JSON.stringify(mr, null, 2) }],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    server.tool(
      'set_merge_request_title',
      'Set the title of a merge request',
      {
        project_id: z.number().describe('The project ID of the merge request'),
        merge_request_iid: z
          .number()
          .describe('The internal ID of the merge request within the project'),
        title: z.string().describe('The title of the merge request'),
      },
      async ({ project_id, merge_request_iid, title }) => {
        try {
          const mr = await api.MergeRequests.edit(
            project_id,
            merge_request_iid,
            { title }
          );
          return {
            content: [{ type: 'text', text: JSON.stringify(mr, null, 2) }],
          };
        } catch (error: unknown) {
          return formatErrorResponse(error as Error);
        }
      }
    );

    // Connect to the MCP server
    await server.connect(transport);
  } else {
    // Invalid request
    res.status(400).json({
      jsonrpc: '2.0',
      error: {
        code: -32000,
        message: 'Bad Request: No valid session ID provided',
      },
      id: null,
    });
    return;
  }

  // Handle the request
  await transport.handleRequest(req, res, req.body);
});

// Reusable handler for GET and DELETE requests
const handleSessionRequest = async (
  req: express.Request,
  res: express.Response
) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
};

// Handle GET requests for server-to-client notifications via SSE
app.get('/', handleSessionRequest);

// Handle DELETE requests for session termination
app.delete('/', handleSessionRequest);

const PORT = parseInt(process.env.REMOTE_GITLAB_MCP_SERVER_PORT || '3000');
const HOSTNAME = process.env.REMOTE_GITLAB_MCP_SERVER_HOSTNAME || '0.0.0.0';
const BACKLOG = parseInt(process.env.REMOTE_GITLAB_MCP_SERVER_BACKLOG || '32');

wrapper.listen(PORT, HOSTNAME, BACKLOG, () => {
  console.log(
    `Remote Gitlab MCP Streamable HTTP Server listening on ${HOSTNAME}:${PORT}`
  );
});
