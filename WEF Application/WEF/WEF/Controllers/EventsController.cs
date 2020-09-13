using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WEF.Data;
using WEF.Models;

namespace WEF.Controllers
{
    [Microsoft.AspNetCore.Authorization.Authorize]
    public class EventsController : Controller
    {
        private readonly EventCollectionsContext _context;

        public EventsController(EventCollectionsContext context)
        {
            _context = context;
        }

        // GET: Events
        public async Task<IActionResult> Index(int? eventsID, string sortOrder, string currentFilter, string searchString, int? pageNumber)
        {
            var viewModel = new EventsIndexData
            {
                Events = await _context.GeneralEvents
                  .AsNoTracking()
                  .OrderBy(i => i.Id)
                  .ToListAsync().ConfigureAwait(true)
            };
            if (eventsID != null)
            {
                ViewData["DevicesID"] = eventsID.Value;
                GeneralEvents eventModels = viewModel.Events.Where(i => i.Id == eventsID.Value).Single();
            }

            ViewData["CurrentSort"] = sortOrder;
            ViewData["Id"] = sortOrder;
            ViewData["LevelDisplayNameParam"] = String.IsNullOrEmpty(sortOrder) ? "leveldisplayname_desc" : "";
            ViewData["LogNameParam"] = String.IsNullOrEmpty(sortOrder) ? "logname_desc" : "";
            ViewData["MachineNameParam"] = String.IsNullOrEmpty(sortOrder) ? "machinename_desc" : "";
            ViewData["MessageParam"] = String.IsNullOrEmpty(sortOrder) ? "message_desc" : "";
            ViewData["ProviderNameParam"] = String.IsNullOrEmpty(sortOrder) ? "providername_desc" : "";
            ViewData["RecordIdParam"] = String.IsNullOrEmpty(sortOrder) ? "recordid_desc" : "";
            ViewData["TaskDisplayNameParam"] = String.IsNullOrEmpty(sortOrder) ? "taskdisplayname_desc" : "";
            ViewData["TimeCreated"] = sortOrder == "Date" ? "date_desc" : "Date";
            
            if (searchString != null)
            {
                pageNumber = 1;
            }
            else
            {
                searchString = currentFilter;
            }

            ViewData["CurrentFilter"] = searchString;

            var events = from e in _context.GeneralEvents
                          select e;
            if (!string.IsNullOrEmpty(searchString))
            {
                events = events.Where(e => e.Message.Contains(searchString) || e.LevelDisplayName.Contains(searchString) || e.LogName.Contains(searchString) || e.MachineName.Contains(searchString) || e.ProviderName.Contains(searchString) || e.TaskDisplayName.Contains(searchString) || e.TimeCreated.ToString().Contains(searchString) || e.RecordId.ToString().Contains(searchString) || e.Id.ToString().Contains(searchString));
            }
            switch (sortOrder)
            {
                case "leveldisplayname_desc":
                    events = events.OrderByDescending(e => e.LevelDisplayName);
                    break;
                case "logname_desc":
                    events = events.OrderByDescending(e => e.LogName);
                    break;
                case "machinename_desc":
                    events = events.OrderByDescending(e => e.MachineName);
                    break;
                case "message_desc":
                    events = events.OrderByDescending(e => e.Message);
                    break;
                case "providername_desc":
                    events = events.OrderByDescending(e => e.ProviderName);
                    break;
                case "recordid_desc":
                    events = events.OrderByDescending(e => e.RecordId);
                    break;
                case "taskdisplayname_desc":
                    events = events.OrderByDescending(e => e.TaskDisplayName);
                    break;
                case "Date":
                    events = events.OrderBy(e => e.TimeCreated);
                    break;
                case "date_desc":
                    events = events.OrderByDescending(e => e.TimeCreated);
                    break;
                default:
                    events = events.OrderByDescending(e => e.Id);
                    break;
            }       
            int pageSize = 10;
            return View(await PaginatedListCollection<GeneralEvents>.CreateAsync(events.AsNoTracking(), pageNumber ?? 1, pageSize));
        }


        // GET: Events/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var events = await _context.GeneralEvents
                .FirstOrDefaultAsync(e => e.Id == id);
            if (events == null)
            {
                return NotFound();
            }

            return View(events);
        }

        // GET: Events/Delete/5
        public async Task<IActionResult> Delete(int? id, bool? saveChangesError = false)
        {
            if (id == null)
            {
                return NotFound();
            }

            var events = await _context.GeneralEvents
                .AsNoTracking()
                .FirstOrDefaultAsync(e => e.Id == id);
            if (events == null)
            {
                return NotFound();
            }
            if (saveChangesError.GetValueOrDefault())
            {
                ViewData["ErrorMessage"] =
                    "Delete failed. Try again, and if the problem persists " +
                    "see your system administrator.";
            }

            return View(events);
        }

        // POST: Events/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var events = await _context.GeneralEvents.FindAsync(id);
            if (events == null)
            {
                return RedirectToAction(nameof(Index));
            }

            try
            {
                _context.GeneralEvents.Remove(events);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (DbUpdateException ex)
            {
                Debug.WriteLine(ex.Message);
                return RedirectToAction(nameof(Delete), new { id = id, saveChangesError = true });
            }
        }

        private bool EventsExists(int id)
        {
            return _context.GeneralEvents.Any(e => e.Id == id);
        }
    }
}
