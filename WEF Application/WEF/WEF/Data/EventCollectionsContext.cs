using Microsoft.EntityFrameworkCore;

namespace WEF.Models
{
    public partial class EventCollectionsContext : DbContext
    {
        public EventCollectionsContext()
        {
        }

        public EventCollectionsContext(DbContextOptions<EventCollectionsContext> options)
            : base(options)
        {
        }

        public virtual DbSet<GeneralEvents> GeneralEvents { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
// #warning To protect potentially sensitive information in your connection string, you should move it out of source code. See http://go.microsoft.com/fwlink/?LinkId=723263 for guidance on storing connection strings.
                optionsBuilder.UseSqlServer("Server=hafnium;Database=EventCollections;Trusted_Connection=True;");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<GeneralEvents>(entity =>
            {
                entity.HasNoKey();

                entity.HasIndex(e => new { e.RecordId, e.MachineName, e.LogName })
                    .HasName("ClusteredIndex-EventCombo")
                    .IsUnique()
                    .IsClustered();

                entity.Property(e => e.LevelDisplayName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.LogName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.MachineName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.Message).IsUnicode(false);

                entity.Property(e => e.ProviderName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.RecordId).HasColumnName("RecordID");

                entity.Property(e => e.TaskDisplayName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.TimeCreated).HasColumnType("smalldatetime");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
